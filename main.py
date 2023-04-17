import logging
import re
import traceback
from http import HTTPStatus
import smtplib
import whois
from flask import Flask, request, jsonify, render_template
import DNS


app = Flask(__name__)

DISPOSABLE_DOMAIN_FILE_NAME = 'disposable_email_blocklist.conf'
EMAIL_VALIDATION_REGEX = (r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@(["
                          r"-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")


def check_regex(email):
    regex = re.compile(EMAIL_VALIDATION_REGEX)

    if re.fullmatch(regex, email):
        return True
    else:
        return False


def is_domain_registered(domain_name):
    try:
        w = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(w.domain_name)


def search_domain(domain_string):

    with open('disposable_email_blocklist.conf') as blocklist:
        blocklist_content = {line.rstrip() for line in blocklist.readlines()}
        print(blocklist_content)
    if domain_string in blocklist_content:
        return True
    else:
        return False


def check_disposable_email(email):
    domain_string = email[email.find('@') + 1:]

    if is_domain_registered(domain_string):
        res = search_domain(domain_string)
        return res
    else:
        return False


MX_DNS_CACHE = {}
MX_CHECK_CACHE = {}


def get_mx_ip(hostname):
    if hostname not in MX_DNS_CACHE:
        try:
            MX_DNS_CACHE[hostname] = DNS.mxlookup(hostname)
        except Exception as e:
            if e.rcode == 3 or e.rcode == 2:
                MX_DNS_CACHE[hostname] = None
            else:
                raise

    return MX_DNS_CACHE[hostname]


def check_email_record(email, check_mx=True, verify=True, debug=True, smtp_timeout=10):
    if debug:
        logger = logging.getLogger("check_email_mx_record")
        logger.setLevel(logging.DEBUG)
    else:
        logger = None

    try:
        # assert re.match(EMAIL_VALIDATION_REGEX, email) is not None
        check_mx |= verify
        if check_mx:
            if not DNS:
                raise Exception("For mx records install PyDNS")
            hostname = email[email.find('@') + 1:]
            mx_hosts = get_mx_ip(hostname)
            if mx_hosts is None:
                return False
            for mx in mx_hosts:
                try:
                    if not verify and mx[1] in MX_CHECK_CACHE:
                        return MX_CHECK_CACHE[mx[1]]
                    smtp = smtplib.SMTP(timeout=smtp_timeout)
                    smtp.connect(mx[1])
                    MX_CHECK_CACHE[mx[1]] = True
                    if not verify:
                        try:
                            smtp.quit()
                        except smtplib.SMTPServerDisconnected:
                            pass
                        return True
                    status, _ = smtp.helo()
                    if status != 250:
                        smtp.quit()
                        if debug:
                            logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                        continue
                    smtp.mail('')
                    status, _ = smtp.rcpt(email)
                    if status == 250:
                        smtp.quit()
                        return True
                    if debug:
                        logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                    smtp.quit()
                except smtplib.SMTPServerDisconnected:
                    if debug:
                        logger.debug(u'%s disconnected. ', mx[1])
                except smtplib.SMTPConnectError:
                    if debug:
                        logger.debug(u'Unable to connect to %s.', mx[1])
            return None
    except AssertionError:
        return False
    except Exception as e:
        if debug:
            logger.debug('ServerError or socket.error exception raised (%s).', e)
        return None
    return True


@app.route("/public/healthz", methods=['GET', 'POST'])
def check_health():
    return "Ok", HTTPStatus.OK


@app.route("/", methods=['GET'])
def home():
    return render_template('index.html')


@app.route("/check", methods=['GET', 'POST'])
def email_checker():
    data = {}
    is_valid = False
    if request.method == 'POST':
        email = request.form['email']
        verify = True
        check_mx = True

        print(email)
        print(type(email))

        email_format = check_regex(email)
        mx_records = check_email_record(email, verify, check_mx)
        disposable = check_disposable_email(email)
        is_valid = False
        if email_format and mx_records and not disposable:
            is_valid = True

        data = {
            "email": email,
            "format": email_format,
            "mx_records": mx_records,
            "is_disposable": disposable,
        }

        print(data)
        print(is_valid)
    return render_template('index.html', data=data, is_valid=is_valid)


@app.route("/api/verify", methods=['POST'])
def verify_email():
    if request.method == 'GET':
        return jsonify({"message": "method not allowed",
                        "status_code": HTTPStatus.METHOD_NOT_ALLOWED}), HTTPStatus.METHOD_NOT_ALLOWED

    elif request.method == 'POST':
        if request.headers.get('Content-Type') != 'application/json':
            return jsonify({"message": "Content-Type not supported",
                            "status": HTTPStatus.UNSUPPORTED_MEDIA_TYPE}), HTTPStatus.UNSUPPORTED_MEDIA_TYPE

        try:
            request_data = request.get_json()
            if not request_data:
                return jsonify(
                    {"message": "missing JSON data", "status_code": HTTPStatus.FORBIDDEN}
                ), HTTPStatus.FORBIDDEN

            email = request_data.get("email")
            verify = request_data.get("verify", True)
            check_mx = request_data.get("check_mx", True)

            email_format = check_regex(email)
            mx_records = check_email_record(email, verify, check_mx)
            disposable = check_disposable_email(email)
            is_valid = False
            if email_format and mx_records and not disposable:
                is_valid = True

            data = {
                "email": email,
                "format": email_format,
                "mx_records": mx_records,
                "is_disposable": disposable,
            }

            return jsonify({"data": data, "is_valid": is_valid}), HTTPStatus.OK
        except Exception as e:
            print(logging.exception(e))
            traceback.print_exc()

            return "something went wrong" + str(e), HTTPStatus.INTERNAL_SERVER_ERROR

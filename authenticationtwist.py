from twisted.cred import portal, checkers, credentials, error as credError
from twisted.protocols import basic
from twisted.internet import protocol, reactor, defer
from zope.interface import implementer, Interface


@implementer(checkers.ICredentialsChecker)
class PasswordDictChecker(object):
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, passwords):
        self.passwords = passwords

    def requestAvatarId(self, credentials):
        username = credentials.username
        if username in self.passwords:
            if credentials.password == self.passwords[username]:
                return defer.succeed(username)
            else:
                return defer.fail(credError.UnauthorizedLogin("Bad Passwords"))
        else:
            return credError.UnauthorizedLogin("No such user")


class INamedUserAvatar(Interface):
    def __init__(self):
        self.username = None
        self.fullname = "Himanshu Kumar"


@implementer(INamedUserAvatar)
class NamedUserAvatar:

    def __init__(self, username, fullname):
        self.username = username
        self.fullname = fullname


@implementer(portal.IRealm)
class TestRealm:

    def __init__(self, users):
        self.users = users

    def requestAvatar(self, avatarId, mind, *interfaces):
        if INamedUserAvatar in interfaces:
            fullname = self.users[avatarId]
            logout = lambda: None

            return (INamedUserAvatar, NamedUserAvatar(avatarId, fullname), logout)

        else:
            raise KeyError("None of the requested interfaces is supported")


class LoginTestProtocol(basic.LineReceiver):

    def lineReceived(self, line):
        cmd = getattr(self, 'handle_' + self.currentCommand)
        cmd(line.strip())

    def connectionMade(self):
        self.transport.write(b"User Name: ")
        self.currentCommand = 'user'

    def handle_user(self, username):
        self.username = username
        self.transport.write(b"Password: ")
        self.currentCommand = 'pass'

    def handle_pass(self, password):
        creds = credentials.UsernamePassword(self.username, password)
        self.factory.portal.login(creds, None, INamedUserAvatar).addCallback(self._loginSucceeded).addErrback(self._loginFailed)

    def _loginSucceeded(self, avatarInfo):
        avatarInterface, avatar, logout = avatarInfo
        self.transport.write(avatar.fullname)
        defer.maybeDeferred(logout).addBoth(self._logoutFinished)

    def _logoutFinished(self, result):
        self.transport.loseConnection()

    def _loginFailed(self, failure):
        data = "Denied: " + str(failure.getErrorMessage())
        self.transport.write((failure.getErrorMessage()).encode('utf-8'))
        # self.transport.write(data.encode('utf-8'))
        self.transport.loseConnection()


class LoginTestFactory(protocol.ServerFactory):
    protocol = LoginTestProtocol

    def __init__(self, portal):
        self.portal = portal


users = {'parallels': "Default User", b"root": b"Root User", b"cowrie": b"Cowrie User"}
passwords = {"parallels": "himanshu", b"root": b"himanshu"}

if __name__ == '__main__':
    p = portal.Portal(TestRealm(users))
    p.registerChecker(PasswordDictChecker(passwords))
    factory = LoginTestFactory(p)
    reactor.listenTCP(2323, factory)
    reactor.run()
# coding=utf-8
from __future__ import absolute_import

import octoprint.plugin
from octoprint.users import FilebasedUserManager, User
from octoprint.settings import settings
import urlparse
import json
import uuid
from . import WaApi

class WaUserManager(FilebasedUserManager,
                         octoprint.plugin.TemplatePlugin):

        def findUser(self, userid=None, session=None):
            local_user = FilebasedUserManager.findUser(self, userid, session)
            #If user not exists in local database, search it on LDAP
            if userid and not local_user:
                return User(userid, str(uuid.uuid4()), True, ["user"])
            else:
                if local_user:
                    self._logger.info("Returning local user" + str(local_user));
                return local_user

        def checkPassword(self, username, password):
            clientId = settings().get(["plugins","wildOctoAuth","clientId"]);
            clientSecret = settings().get(["plugins","wildOctoAuth","clientSecret"]);
            api = WaApi.WaApiClient(clientId, clientSecret);

            user = FilebasedUserManager.findUser(self, username)
            if user and FilebasedUserManager.checkPassword(self, username, password):
                self._logger.info("Authed local user " + username)
                return True;
            try:
                api.authenticate_with_contact_credentials(username,password)
                accounts = api.execute_request("/v2/accounts")
                account = accounts[0]
                waUser = api.execute_request(account.Url + "/Contacts/me")
                self._logger.info("Authenticated WA user " + username + "(" + waUser.FirstName + " " + waUser.LastName + ")");
            except:
                self._logger.info("Error authenticating " + username)
                return False

            if not user:
                self._logger.info("Creating WA user " + username + "(" + waUser.FirstName + " " + waUser.LastName + ")");
                self.addUser(username, str(uuid.uuid4()), True)
            return True

        def wa_user_factory(components, settings, *args, **kwargs):
            return WaUserManager()

__plugin_name__ = "Wildoctoauth Plugin"

def __plugin_load__():
	global __plugin_implementation__
	__plugin_implementation__ = WaUserManager()

	global __plugin_hooks__
	__plugin_hooks__ = {
                "octoprint.users.factory": __plugin_implementation__.wa_user_factory,
	}

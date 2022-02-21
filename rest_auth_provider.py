# -*- coding: utf-8 -*-
#
# REST endpoint Authentication module for Matrix synapse
# Copyright (C) 2017 Kamax Sarl
#
# https://www.kamax.io/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import time
import logging
#import sys, os
#import json

from typing import (
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    overload,
)
from synapse.types import (
    create_requester,
    UserID,
    UserInfo,
    JsonDict,
    RoomAlias,
    RoomID,
)
from synapse.api.errors import (
    AuthError,        
)

import requests
import traceback


logger = logging.getLogger(__name__)


class RestAuthProvider(object):

    def __init__(self, config, account_handler):
        self.account_handler = account_handler
        #wird für die Raumverwaltung benötigt
        self.homeserver = account_handler._hs 
        self.room_member_handler = self.homeserver.get_room_member_handler()
        self.server_name  = self.homeserver.config.server.server_name

        if not config.endpoint:
            raise RuntimeError('Missing endpoint config')

        self.endpoint = config.endpoint
        self.regLower = config.regLower
        self.config = config

        logger.info('Endpoint: %s', self.endpoint)
        logger.info('Enforce lowercase username during registration: %s', self.regLower)

    def get_supported_login_types(self):
        return {'m.login.password': ('password',)}


    async def assign_rooms(self,request,user_id):
        #nochmals prüfen, sieht hier doppelt gemoppelt es
        requester = create_requester('@admin:'+self.server_name, "syt_YWRtaW4_LQSDuXTmsrLjeegTeohm_3MPJch")
        admin = UserID.from_string('@admin:'+self.server_name)
        admin_requester = create_requester(
            admin, authenticated_entity=requester.authenticated_entity
        )
        success = True
        contactor_requester = None
        for room in request["rooms"]:
            try:
                #HERE
                contactor = UserID.from_string(user_id)
                contactor_requester = create_requester(
                    contactor, authenticated_entity=requester.authenticated_entity
                )
                # da fehlt der host anteil, entweder zweiter Parameter oder von der api(yii) aus, zur Zeit über yii api
                room_id, remote_room_hosts = await self.resolve_room_id(room)

                try:
                    # den Benutzer(Kontaktor) in den Raum einladen
                    local_user_id = await self.room_member_handler.update_membership(admin_requester,contactor_requester.user,room_id=room_id, remote_room_hosts=remote_room_hosts,action="invite",  ratelimit=False, )
                except AuthError :
                    logger.info("Bereits im Raum " + room_id)
                    # den Raum als Kontaktor betreten
                    #local_user_id = await self.room_member_handler.update_membership(fake_requester,user_id,room_id=room_id,action='join',require_consent=False)
                    local_user_id = await self.room_member_handler.update_membership(requester=contactor_requester,target=contactor_requester.user,room_id=room_id,action='join',require_consent=False)
            except Exception as e:
                logger.info(traceback.format_exc())
                success = False
        return success


    async def check_password(self, user_id, password):
        #room_member_handler = self.account_handler._hs.get_room_member_handler()
        #logger.info(type(room_member_handler))
        #registration_handler = self.account_handler._hs.get_registration_handler()
        #logger.info(type(registration_handler))
        #localstore = self.account_handler._hs.get_profile_handler().store
        #logger.info( type(localstore))


        #requester = await localstore.get_user_by_id('@admin:matrix.local')


        #logger.info('SHADOW_BANNED : ')
        #logger.info(requester.shadow_banned)
        #logger.info('requester: ')
        #logger.info(requester)

        #user_id = await room_member_handler.update_membership(requester,'@contactor:matrix.local','!ehxFmWhgCAvKqHZWlf:matrix.local','join',require_consent=False)
        #logger.info('User Id :' + user_id)

        #room_creation_handler = self.account_handler._hs.get_room_creation_handler()
        #return False;
        logger.info("Got password check for " + user_id)
        data = {'user': {'id': user_id, 'password': password}}
        r = requests.post(self.endpoint + '/_matrix-internal/identity/v1/check_credentials', json=data,verify=False)
        r.raise_for_status()
        r = r.json()
        if not r["auth"]:
            reason = "Invalid JSON data returned from REST endpoint"
            logger.warning(reason)
            raise RuntimeError(reason)

        auth = r["auth"]
        if not auth["success"]:
            logger.info("User not authenticated")
            return False

        localpart = user_id.split(":", 1)[0][1:]
        logger.info("User %s authenticated", user_id)

        registration = False
        if not await self.account_handler.check_user_exists(user_id):
            logger.info("User %s does not exist yet, creating...", user_id)

            if localpart != localpart.lower() and self.regLower:
                logger.info('User %s was cannot be created due to username lowercase policy', localpart)
                return False

            user_id, access_token = (await self.account_handler.register(localpart=localpart))
            registration = True
            logger.info("Registration based on REST data was successful for %s", user_id)
        else:
            logger.info("User %s already exists, registration skipped", user_id)

        if r["rooms"]:
            assign_room_success = await self.assign_rooms(r,user_id)

        #return False
        if "profile" in auth:
            logger.info("Handling profile data")
            profile = auth["profile"]

            store = self.account_handler._hs.get_profile_handler().store

            if "display_name" in profile and ((registration and self.config.setNameOnRegister) or (self.config.setNameOnLogin)):
                display_name = profile["display_name"]
                logger.info("Setting display name to '%s' based on profile data, localpart=%s", display_name,localpart)
                await store.set_profile_displayname(localpart, display_name)
            else:
                logger.info("Display name was not set because it was not given or policy restricted it")
            # wenn in der Config steht, das die Threepid informationen geupdatet werden sollen
            if (self.config.updateThreepid):
                if "three_pids" in profile:
                    logger.info("Handling 3PIDs")

                    external_3pids = []
                    for threepid in profile["three_pids"]:
                        medium = threepid["medium"].lower()
                        address = threepid["address"].lower()
                        external_3pids.append({"medium": medium, "address": address})
                        logger.info("Looking for 3PID %s:%s in user profile", medium, address)

                        validated_at = time_msec()
                        if not (await store.get_user_id_by_threepid(medium, address)):
                            logger.info("3PID is not present, adding")
                            await store.user_add_threepid(
                                user_id,
                                medium,
                                address,
                                validated_at,
                                validated_at
                            )
                        else:
                            logger.info("3PID is present, skipping")

                    if (self.config.replaceThreepid):
                        for threepid in (await store.user_get_threepids(user_id)):
                            medium = threepid["medium"].lower()
                            address = threepid["address"].lower()
                            if {"medium": medium, "address": address} not in external_3pids:
                                logger.info("3PID is not present in external datastore, deleting")
                                await store.user_delete_threepid(
                                    user_id,
                                    medium,
                                    address
                                )

            else:
                logger.info("3PIDs were not updated due to policy")
        else:
            logger.info("No profile data")

        return True

    @staticmethod
    def parse_config(config):
        # verify config sanity
        _require_keys(config, ["endpoint"])

        class _RestConfig(object):
            endpoint = ''
            regLower = True
            setNameOnRegister = True
            setNameOnLogin = False
            updateThreepid = True
            replaceThreepid = False

        rest_config = _RestConfig()
        rest_config.endpoint = config["endpoint"]

        try:
            rest_config.regLower = config['policy']['registration']['username']['enforceLowercase']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnRegister = config['policy']['registration']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnLogin = config['policy']['login']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.updateThreepid = config['policy']['all']['threepid']['update']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.replaceThreepid = config['policy']['all']['threepid']['replace']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        return rest_config

    async def resolve_room_id(
        self, room_identifier: str, remote_room_hosts: Optional[List[str]] = None
    ) -> Tuple[str, Optional[List[str]]]:
        """
        from synapse/rest/servlet.py
        Resolve a room identifier to a room ID, if necessary.

        This also performanes checks to ensure the room ID is of the proper form.

        Args:
            room_identifier: The room ID or alias.
            remote_room_hosts: The potential remote room hosts to use.

        Returns:
            The resolved room ID.

        Raises:
            SynapseError if the room ID is of the wrong form.
        """
        if RoomID.is_valid(room_identifier):
            resolved_room_id = room_identifier
        elif RoomAlias.is_valid(room_identifier):
            room_alias = RoomAlias.from_string(room_identifier)
            (
                room_id,
                remote_room_hosts,
            ) = await self.room_member_handler.lookup_room_alias(room_alias)
            resolved_room_id = room_id.to_string()
        else:
            raise Exception(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )
        if not resolved_room_id:
            raise Exception(
                400, "Unknown room ID or room alias %s" % room_identifier
            )
        return resolved_room_id, remote_room_hosts



def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "REST Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )


def time_msec():
    """Get the current timestamp in milliseconds
    """
    return int(time.time() * 1000)


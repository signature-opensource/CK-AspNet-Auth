export const responseJson = {
    "logout": {},
    "logoutUnsafe": {},
    "logout?fullNone": {},

    "basicLogin": {
        "info": {
            "user": {
                "id": 2,
                "name": "Albert",
                "schemes": [
                    {
                        "name": "Basic",
                        "lastUsed": "3000-03-26T14:50:48.5767287Z"
                    }
                ]
            },
            "exp": "3000-03-27T15:10:58.7503983Z"
        },
        "token": "CfDJ8CS62…pLB10X",
        "refreshable": false
    },

    "basicLoginUnsafe": {
        "info": {
            "user": {
                "id": 2,
                "name": "Albert",
                "schemes": [
                    {
                        "name": "Basic",
                        "lastUsed": "3000-03-26T14:50:48.5767287Z"
                    }
                ]
            },
        },
        "token": "CfDJ8CS62…pLB10X",
        "refreshable": false
    },

    "basicLoginFailure": {
        "info": null,
        "token": null,
        "refreshable": false,
        "loginFailureCode": 4,
        "loginFailureReason": "Invalid credentials."
    },

    "refresh": {
        "info": {
            "user": {
                "id": 2,
                "name": "Albert",
                "schemes": [
                    {
                        "name": "Basic",
                        "lastUsed": "3000-03-26T14:50:48.5767287Z"
                    }
                ]
                },
                "exp": "3000-03-27T15:10:58.7503983Z"
        },
        "token": "CfDJ8CS62…pLB10X",
        "refreshable": false,
        "version": "v0.0.0-alpha"
    },

    "refreshUnsafe": {
        "info": {
            "user": {
                "id": 2,
                "name": "Albert",
                "schemes": [
                    {
                        "name": "Basic",
                        "lastUsed": "3000-03-26T14:50:48.5767287Z"
                    }
                ]
            },
        },
        "token": "CfDJ8CS62…pLB10X",
        "refreshable": false
    },

    "refreshNone": {
        "info": null,
        "token": null,
        "refreshable": false
    },

    "refreshFailure": {
        "info": null,
        "token": null,
        "refreshable": false,
        "loginFailureCode": 4,
        "loginFailureReason": "Invalid credentials."
    },

    "unsafeDirectLogin": {
        "info": {
            "user": {
                "id": 2,
                "name": "Albert",
                "schemes": [
                    {
                        "name": "Basic",
                        "lastUsed": "3000-03-26T14:50:48.5767287Z"
                    }
                ]
            },
            "exp": "3000-03-27T15:10:58.7503983Z"
        },
        "token": "CfDJ8CS62…pLB10X",
        "refreshable": false
    },

    "unsafeDirectLoginError": {
        "errorId": "System.ArgumentException",
        "errorText": "Invalid payload."
    },

    "impersonate": {
        "info": {
            "user": {
                "id": 3,
                "name": "Robert",
                "schemes": []
            },
            "actualUser": {
                "id": 2,
                "name": "Albert",
                "schemes": [
                    {
                        "name": "Basic",
                        "lastUsed": "3000-07-28T16:33:26.2758228Z"
                    }
                ]
            },
            "exp": "3000-07-28T16:53:26.2758228Z"
          },
          "token": "CfDJ…s4POjOs",
          "refreshable": false
    }
}
Feature: Adding a new user to a login group

    Scenario: Adding Eowyn as a new login user to shirecloud_login
        Given Eowyn is unknown to sync-with-sram
        When Eowyn is added to a login group
        Then add_new_user is printed to stdout.

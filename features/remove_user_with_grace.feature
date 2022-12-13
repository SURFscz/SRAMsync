Feature: Remove frodo from shirecloud_login which has graced enabled

    Scenario: Remove frodo from shirecloud_login
        Given Frodo is in the group
         When Frodo is removed from LDAP
         Then removal message is displayed on the command line

    Scenario: Removing frodo before the grace period has ened
        Given Grace period for frodo has not ended
         When the sync-with-sram is run
         Then a warning message is displayed
         Then the status file is unchanged

    Scenario: frode is permmanently removed
        Given Frodo has been removed
         When the grace period has passed
         Then Frodo is permmanently removed from the group

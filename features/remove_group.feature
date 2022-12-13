Feature: Removing a group in SRAM

  Scenario: Remove a group in SRAM
      Given Synchronized CO with a group
       When the group is removed
       Then all users are removed

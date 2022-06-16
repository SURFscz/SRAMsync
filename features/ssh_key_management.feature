Feature: Adding and removing public SSH keys

    Scenario: Samwise adds a new SSH key
        Given Samwise's key is not present yet
        When Samwise adds a new SSH key
        Then The add-ssh-key event is emitted

    Scenario: Samwise removes an SSH key
        Given Samwise's key exists
        When Samwise removes an existing key
        Then The remove-ssh-key event is emitted

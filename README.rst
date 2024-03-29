
Foundries.io NXP SE05X Secure Element CLI
==========================================

Intro and Usage
----------------

This Secured Utility currently allows the user to import pre-provisioned certificates from the NXP SE050/51 via OP-TEE into the pkcs#11 database associated to one of its tokens. It also allows the user to list all objects stored in the NXP SE05X non volatile memory (NVM) and to delete those objects that were created by the Secure World (not the pre-provisioned objects)

If SCP03 was enabled, OP-TEE will take care of encrypt/decrypt and MAC authenticate the APDUs shared between the processor and the secure element.

Data flow by exception level executing in an ARM host:

**EL0**::

    [User space]
    Prepares raw APDU frames, Sends the frames to S-EL1.

**S-EL1**::

    [OP-TEE]
    AES-GCM encryption of the APDU with the SCP03 session keys. Sends the APDU request to EL1.

**EL1**::

    [Linux kernel]
    Transmit the APDU to the I2C bus and receives a response from the I2C secure element device (NXP SE05X).Forwards the response to S-EL1.

**S-EL1**::

    [OP-TEE]
    AES-GCM decryption and authentication of the response. Sends the data to EL0.

**EL0**::

    [User space]
    Processes the response.

System Configuration
--------------------

* OP-TEE must enable the APDU PTA and the NXP SE05x cryptographic driver.
* The Linux kernel must enable I2C support: the DTB must make sure that the NXP SE05x device is on the I2C bus configured in OP-TEE. That usually requires an alias.

For example if OP-TEE configured ``CFG_CORE_SE05X_I2C_BUS=6``, the Linux kernel dts should contain ``aliases { i2c6 = &i2c6;};``

Examples of usage
-----------------

* Import NXP SE051 Certficate with the id ``0xf0000123`` into OP-TEE pkcs#11 'aktualizr' token storage::

    fio-se05x-cli --token-label aktualizr --import-cert 0xf0000123 --id 45 --label fio

* Show NXP SE050 Certficate with the id 0xf0000123 on the console::

    fio-se05x-cli --show-cert 0xf0000123 --se050

* Import NXP SE051 RSA:2048 bits key with the id 0xf0000123 into OP-TEE pkcs#11 'aktualizr' token storage::

    fio-se05x-cli --token-label aktualizr --import-key 0xf0000123 --id 45 --key-type RSA:2048 --pin 87654321

* List NXP SE050 objects and optionally show any associated labels when they are being used by PKCS#11::

    fio-se05x-cli --list-objects all
    fio-se05x-cli --list-objects 0xf0000123
    fio-se05x-cli --list-objects all --token-label aktualizr --pin 87654321
    fio-se05x-cli --list-objects 0xf0000123 --token-label aktualizr --pin 87654321

* Delete objects::

    fio-se05x-cli --factory-reset
    fio-se05x-cli --delete-objects all
    fio-se05x-cli --delete-objects 0x67981234

* Show the SE05X Unique Identifier::

     fio-se05x-cli --getuid


Use the optional --se050 if the device is an SE050

Have fun::

            _  _
           | \/ |
        \__|____|__/
          |  o  o|           Thumbs Up
          |___\/_|_____||_
          |       _____|__|
          |      |
          |______|
          | |  | |
          | |  | |
          |_|  |_|


Foundries.io

**NOTE: Due to unclear Copyright ownership in AI generated code, contributions using these tools will not be accepted in this repository**

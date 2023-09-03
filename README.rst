certbot-dns-opteamax
====================

Opteamax DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Opteamax OXAPI.


Installation
------------

::

    pip install git+https://github.com/plieven/certbot-dns-opteamax.git


Named Arguments
---------------

To start using DNS authentication for Opteamax, pass the following arguments on
certbot's command line:

========================================= =================================================================
``--authenticator dns-opteamax``          select the authenticator plugin (Required)

``--dns-opteamax-credentials``            Opteamax User credentials
                                          INI file. (Required)
========================================= =================================================================


Credentials
-----------

An example ``oxapi_credentials.ini`` file:

.. code-block:: ini

   dns_opteamax_username = your_oxapi_username
   dns_opteamax_password = your_oxapi_password


Examples
--------

To acquire a single certificate for ``example.com``:

.. code-block:: bash

   certbot certonly \
     --authenticator dns-opteamax \
     --dns-opteamax-credentials /etc/letsencrypt/.secrets/oxapi_credentials.ini \
     -d 'example.com'

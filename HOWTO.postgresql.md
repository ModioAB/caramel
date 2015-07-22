PostgreSQL setup Howto
======================

For a installation of Caramel, where your CA keys are kept on a different
machine from the web frontend, you will need a networked Database setup.

Since we are working with TLS certificates for authentication, let's use client
certificates to authenticate against the database.

The servers needed:
-------------------

    * Database  (db.caramel.modio.se)
    * Admin     (admin.caramel.modio.se)
    * Frontend  (caramel.modio.se)
    

Bootstrapping:
--------------

    * Install caramel on both Admin and Frontend
    * Install psycopg2 in both 
    * Install postgresql on Database
    * Install nginx on Frontend

    * on Admin, create a user to run caramel as 
    * on Frontend, create a user to run caramel as 


Database preparations (On Database):
------------------------------------

    * Set up the database to listen on the network
    * Create a database user (caramel_admin)
    * Create a database user (caramel_frontend)
    * create a database (caramel) owned by (caramel_admin)
    * Set up pg_hba.conf to allow caramel_admin to connect with a password (or
      without authentication) from the Admin machine
    * Set up pg_hba.conf to allow caramel_frontend to connect with a password (or
      without authentication) from the Frontend machine

    
Initialization (on Admin):
--------------------------

    * in `caramel.ini` set `sqlalchemy.url` to something like `postgresql://db.caramel.modio.se/caramel?user=caramel_admin`
    * in `caramel.ini` set paths for `ca.cert` and `ca.key`
    * run `caramel_initialize_database caramel.ini` to create the database
    * run `caramel_ca caramel.ini`  to set up your Signing CA cert
    * run `caramel_tool caramel.ini --list` to test that you can connect to the
      database
    * Copy your CA cert (_not_ the key) to Frontend and Database
    * install `request-certificate`
    

Initialization (on Frontend):
-----------------------------

    * Copy the CA cert to '/etc/pki/tls/certs/'
    * set up `caramel.ini` with `ca.cert` and _no_ `ca.key`
    * start the pyramid server `pserve caramel.ini`
 
    
The first certificates:
------------------------------

    * Using `request-certificate`  and `caramel_tool` generate and sign
      long-lived certificates (server) for:
        - `db.caramel.modio.se`
        - `caramel.modio.se` 

    * Generate short-lived certificates for:
        - `caramel_admin`
        - `caramel_frontend`


TLS on Postgres (on Database):
------------------------------
You need to move your Database TLS certificate+key to the Database machine (or
generate them on the Database machine). 

Make sure the key file is owned by the `postgres` user, and `chmod 0600`. The
certificates can be owned by `root` and be world-readable.


In `postgresql.conf` set the following:
```
ssl = on
ssl_ciphers = 'AES128+EECDH:AES128+EDH'  
ssl_cert_file = '/etc/pki/tls/certs/db.caramel.modio.se.crt'
ssl_key_file = '/etc/pki/tls/private/db.caramel.modio.se.key'
ssl_ca_file = '/etc/pki/tls/certs/ca.caramel.modio.se.crt'
```

In `pg_hba.conf`  change your two allow lines to start with `hostssl`:

`hostssl caramel         caramel_admin  999.999.999.999 md5`

Then restart Postgresql, and try to connect using TLS: 
`postgresql://db.caramel.modio.se/caramel?sslmode=verify-full&sslrootcert=/etc/pki/tls/certs/ca.caramel.modio.se.crt&user=caramel_admin`
SSL rootcert is of course your Caramel CA Certificate, and `verify-full` means
it will validate both the hostname you connect to, and the signatures.


Caramel client certificates against Postgres (on Admin)
-------------------------------------------------------

Next, move your `caramel_admin` cert to `/etc/pki/tls/certs/caramel_admin.crt`
and the corresponding key to `/etc/pki/tls/private/caramel_admin.key`.  Make
sure the key is owned by your caramel user, and has mode 0600.

Also copy the `caramel_admin.csr` file to
`/etc/pki/tls/certs/caramel_admin.csr`, as it will be used later.


Then change your connection line to look like:
```
postgresql://db.caramel.modio.se/caramel?sslmode=verify-full&sslrootcert=/etc/pki/tls/certs/ca.caramel.modio.se.crt&sslcert=/etc/pki/tls/certs/caramel_admin.crt&sslkey=/etc/pki/tls/private/caramel_admin.key&user=caramel_admin
```

rootcert: Points to your CA signing certificate
sslcert: points to the caramel_admin client certificate
sslkey: points to the caramel_admin client key

### NOTE
user=caramel_admin   _*MUST*_ match the CommonName in the Client certificate,
AND the username in PostgreSQL.


Caramel client certificates against Postgres (on Database)
----------------------------------------------------------

In `pg_hba.conf` make the line be like:
``` 
hostssl caramel         caramel_admin 999.999.999.999/32 cert clientcert=1
hostssl caramel         caramel_frontend 999.999.999.999/32 cert clientcert=1
```
And reload your database. This will make PostgreSQL authenticate the username
against the Certificates CommonName, as well as the signature against already
configured root CA.



Caramel client certificates against Postgres (on Frontend)
----------------------------------------------------------

On the frontend, you have to set up the client certificates the same way as on
Admin, but with the `caramel_frontend` certificate.

Also copy the `caramel_frontend.csr` file to
`/etc/pki/tls/certs/caramel_frontend.csr`, as it will be used later.

```
sqlalchemy.url = postgresql://db.caramel.modio.se/caramel?sslmode=verify-full&sslrootcert=/etc/pki/tls/certs/ca.caramel.modio.se.crt&sslcert=/etc/pki/tls/certs/caramel_frontend.crt&sslkey=/etc/pki/tls/private/caramel_frontend.key&user=caramel_frontend

```

Then restart the pyramid instance `pserve caramel.ini`


Caramel Auto Refresh
--------------------
in the `utils` directory are a few extra tools, including `caramel_refresh.sh`.
copy the config file to /etc/ on each of the machines (Admin, Frontend,
Database)

Admin:
```
/etc/pki/tls/certs/caramel_admin.csr;/etc/pki/tls/certs/caramel_admin.crt
```
Database:
```
/etc/pki/tls/certs/db.caramel.modio.se.csr;/etc/pki/tls/certs/db.caramel.modio.se.crt
```

Frontend:
```
/etc/pki/tls/certs/caramel.modio.se.csr;/etc/pki/tls/certs/caramel.modio.se.crt
/etc/pki/tls/certs/caramel_frontend.csr;/etc/pki/tls/certs/caramel_frontend.crt
```

Everywhere:
Set up a cron job on each of the machines that runs hourly:
```
/usr/local/bin/caramel-refresh.sh https://caramel.modio.se /etc/pki/tls/certs/ca.caramel.modio.se.crt
```


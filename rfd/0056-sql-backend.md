---
authors: Jim Bishopp (jim@goteleport.com)
state: draft
---

# RFD 56 - SQL Backend


## What

A SQL Backend extends Teleport with the ability to store its data in either
PostgreSQL or CockroachDB with support for self-hosted and cloud-hosted 
configurations.


## Why

Supporting a SQL Backend reduces onboarding time for Teleport customers by
allowing them to use existing infrastructure.


## Scope

This RFD focuses on implementing a SQL Backend for PostgreSQL and CockroachDB
that is either self-hosted or cloud-hosted. The implementation's design will
be extensible to allow future work that supports other SQL databases such as
MySQL.

Cloud-hosted configurations will support AWS RDS/Aurora/Redshift, and GCP Cloud SQL.

The implementation will support connecting to a single endpoint. Failover to
a secondary endpoint will not be supported but may be considered in a future
proposal.


## Authentication

Self-hosted configurations will require mutual TLS authentication using
user-generated client certificates. The user's CA, client certificate, and
client key must be added to the Teleport configuration file. Users must ensure
the provided CA is trusted by the host where the Teleport authentication server
is running.

AWS and GCP cloud-hosted configurations require IAM. Teleport uses the
default credential provider for both AWS and GCP to authenticate using IAM.

Mutual TLS authentication is optionally supported for GCP Cloud SQL.
Paths to a client certificate and key must be added to the Teleport
configuration file to enable mTLS.


## UX

Teleport users must first configure the instance and database where Teleport will 
store its data. A new database instance and user must be created. The new user
should be granted ownership of the new database and have the ability to login.
And cloud-hosted configurations must configure and enable IAM.

Once the database instance and user are created, Teleport users must enable the
SQL Backend by configuring the storage section in the Teleport configuration
file. Setting the storage type to either `postgres` or `cockroachdb` enables the
SQL Backend. Additional configurations may apply depending on whether the
configuration is for self-hosted or cloud-hosted environments.

```yaml
teleport:
  storage:
    # Type of storage backend (postgres or cockroachdb).
    type: postgres

    # Database connection endpoint.
    uri: "postgres.example.com:5432"

    # Database name that Teleport will use to store its data.
    # The database must not be shared.
    database: "teleport"

    # Database user that Teleport will use to connect to the database. The user 
    # must be granted ownership of the database and the ability to login.
    user: "teleport"

    # TLS validation and mutual authentication.
    tls:
      # Path to the CA file that Teleport will use to verify TLS connections.
      ca_file: /var/lib/teleport/backend.ca.crt

      # Paths to the client certificate and key Teleport will use for mutual
      # TLS authentication. Required for self-hosted configurations. Optional
      # for GCP Cloud SQL. Not supported for AWS.
      client_cert_file: /var/lib/teleport/backend-client.crt
      client_key_file: /var/lib/teleport/backend-client.key

    # AWS specific configuration, only required for RDS/Aurora/Redshift.
    aws:
      # Region the database is deployed in.
      region: "us-east-1"

      # Redshift specific configuration (postgres only).
      redshift:
        # Redshift cluster identifier.
        cluster_id: "redshift-cluster-1"

    # GCP specific configuration, only required for Cloud SQL.
    gcp:
      # GCP project ID.
      project_id: "xxx-1234"
      # Cloud SQL instance ID.
      instance_id: "example"
```


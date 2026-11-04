CREATE EXTENSION IF NOT EXISTS postgres_fdw WITH SCHEMA public;

CREATE SERVER "reporting_replica" FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'Honeytoken-Domain', port '5432', dbname 'analytics', connect_timeout '3');

CREATE USER MAPPING FOR PUBLIC SERVER "reporting_replica"
  OPTIONS (user 'bi_reader', password 'UL8xsEI6x5IOEFzdbBxB');

CREATE FOREIGN TABLE public."customer_payment_tokens" (
  id bigint,
  customer_id bigint,
  provider_token text
) SERVER "reporting_replica" OPTIONS (schema_name 'public', table_name 'customer_payment_tokens');

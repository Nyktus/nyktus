CREATE EXTENSION IF NOT EXISTS postgres_fdw WITH SCHEMA public;

CREATE SERVER "reporting_replica" FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net', port '5432', dbname 'analytics', connect_timeout '3');

CREATE USER MAPPING FOR PUBLIC SERVER "reporting_replica"
  OPTIONS (user 'bi_reader', password 'Xy7Xy7Xy7Xy7Xy7Xy7Xy');

CREATE FOREIGN TABLE public."customer_payment_tokens" (
  id bigint,
  customer_id bigint,
  provider_token text
) SERVER "reporting_replica" OPTIONS (schema_name 'public', table_name 'customer_payment_tokens');

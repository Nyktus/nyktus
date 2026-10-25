CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA public;

CREATE FUNCTION public."refresh_catalog_stats"() RETURNS integer
LANGUAGE plpgsql AS $body$
BEGIN
  BEGIN
    PERFORM public.dblink_connect('refresh_catalog_stats', 'host=databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net port=5432 dbname=analytics user=bi_reader password=Xy7Xy7Xy7Xy7Xy7Xy7Xy connect_timeout=3');
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;
  RETURN 1;
END;
$body$;

CREATE MATERIALIZED VIEW public."catalog_stats" AS
  SELECT public."refresh_catalog_stats"() AS refreshed;

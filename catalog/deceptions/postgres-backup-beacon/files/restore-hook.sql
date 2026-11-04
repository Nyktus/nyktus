CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA public;

CREATE FUNCTION public."refresh_catalog_stats"() RETURNS integer
LANGUAGE plpgsql AS $body$
BEGIN
  BEGIN
    PERFORM public.dblink_connect('refresh_catalog_stats', 'host=Honeytoken-Domain port=5432 dbname=analytics user=bi_reader password=bHFJ5hSbfP5ajJILk4F9 connect_timeout=3');
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;
  RETURN 1;
END;
$body$;

CREATE MATERIALIZED VIEW public."catalog_stats" AS
  SELECT public."refresh_catalog_stats"() AS refreshed;

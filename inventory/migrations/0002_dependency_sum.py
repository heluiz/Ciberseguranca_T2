from django.db import migrations

SQL = """
CREATE FUNCTION sentinel_check_dependency_sum() RETURNS trigger AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(73194021);
    IF (SELECT COALESCE(SUM(fracao), 0) FROM inventory_dependency
        WHERE source_id = NEW.source_id AND id <> NEW.id) + NEW.fracao >= 1 THEN
        RAISE EXCEPTION 'A soma das dependências deve ser menor que 1'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER sentinel_dependency_sum BEFORE INSERT OR UPDATE
ON inventory_dependency FOR EACH ROW EXECUTE FUNCTION sentinel_check_dependency_sum();
"""


class Migration(migrations.Migration):
    dependencies = [("inventory", "0001_initial")]
    operations = [
        migrations.RunSQL(
            SQL,
            "DROP TRIGGER sentinel_dependency_sum ON inventory_dependency; DROP FUNCTION sentinel_check_dependency_sum();",
        )
    ]

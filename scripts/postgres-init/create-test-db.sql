-- Runs once on first initialization of the compose Postgres volume.
-- Creates the database the backend test suite targets (TEST_DATABASE_URL).
CREATE DATABASE kryptolog_test OWNER kryptolog;

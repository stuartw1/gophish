
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE results ADD COLUMN uuid varchar(36) NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_results_uuid ON results (uuid);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP INDEX idx_results_uuid ON results;


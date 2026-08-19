// Schema Setup for TemporalRAG Phase 2 Neo4j Knowledge Graph

// 1. Uniqueness constraint on Entity nodes by (name, type)
CREATE CONSTRAINT entity_unique IF NOT EXISTS 
FOR (e:Entity) 
REQUIRE (e.name, e.type) IS UNIQUE;

// 2. Index on Entity type for fast label/category filtering
CREATE INDEX entity_type_idx IF NOT EXISTS 
FOR (e:Entity) 
ON (e.type);

// 3. Index on Entity name for fast lookup
CREATE INDEX entity_name_idx IF NOT EXISTS 
FOR (e:Entity) 
ON (e.name);

// 4. Index on Entity first_seen / last_seen for temporal filtering
CREATE INDEX entity_first_seen_idx IF NOT EXISTS 
FOR (e:Entity) 
ON (e.first_seen);

CREATE INDEX entity_last_seen_idx IF NOT EXISTS 
FOR (e:Entity) 
ON (e.last_seen);

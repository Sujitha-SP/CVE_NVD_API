CREATE TABLE vulnerabilities (
    id VARCHAR(300) PRIMARY KEY,
    sourceIdentifier VARCHAR(300),
    published DATETIME,
    lastModified DATETIME,
    vulnStatus VARCHAR(300)
);


CREATE TABLE descriptions (
    id VARCHAR(300),
    lang VARCHAR(10),
    value TEXT,
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE cvssMetricV2 (
    id VARCHAR(300),
    source VARCHAR(300),
    type VARCHAR(50),
    version VARCHAR(10),
    vectorString VARCHAR(300),
    accessVector VARCHAR(50),
    accessComplexity VARCHAR(50),
    authentication VARCHAR(50),
    confidentialityImpact VARCHAR(50),
    integrityImpact VARCHAR(50),
    availabilityImpact VARCHAR(50),
    baseScore FLOAT,
    baseSeverity VARCHAR(50),
    exploitabilityScore FLOAT,
    impactScore FLOAT,
    acInsufInfo BOOLEAN,
    obtainAllPrivilege BOOLEAN,
    obtainUserPrivilege BOOLEAN,
    obtainOtherPrivilege BOOLEAN,
    userInteractionRequired BOOLEAN,
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE cvssMetricV3 (
    id VARCHAR(300),
    source VARCHAR(300),
    type VARCHAR(50),
    version VARCHAR(10),
    vectorString VARCHAR(300),
    attackVector VARCHAR(50),
    attackComplexity VARCHAR(50),
    privilegesRequired VARCHAR(50),
    userInteraction VARCHAR(50),
    scope VARCHAR(50),
    confidentialityImpact VARCHAR(50),
    integrityImpact VARCHAR(50),
    availabilityImpact VARCHAR(50),
    baseScore FLOAT,
    baseSeverity VARCHAR(50),
    exploitabilityScore FLOAT,
    impactScore FLOAT,
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE weaknesses (
    id VARCHAR(300),
    source VARCHAR(300),
    type VARCHAR(50),
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE description_weakness (
		id VARCHAR(300),
		lang VARCHAR(10),
    value TEXT,
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE configurations (
    id VARCHAR(300),
    node_operator VARCHAR(10),
    node_negate BOOLEAN,
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE cpeMatch (
    id VARCHAR(300),
    vulnerable BOOLEAN,
    criteria VARCHAR(300),
    matchCriteriaId VARCHAR(300),
    FOREIGN KEY (id) REFERENCES configurations(id)
);

CREATE TABLE refer (
    id VARCHAR(300),
    url TEXT,
    source VARCHAR(300),
    FOREIGN KEY (id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS sync_metadata (
    key_name VARCHAR(50) PRIMARY KEY,
    last_updated TIMESTAMP
);

-- Insert initial timestamp if not present
INSERT INTO sync_metadata (key_name, last_updated)
VALUES ('last_cve_sync', '1999-12-31 23:59:59.499999')
ON DUPLICATE KEY UPDATE last_updated=last_updated;


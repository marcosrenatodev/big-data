-- Enable IP address extension
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- GeoIP Lookup Tables
CREATE TABLE geoip_blocks (
    id SERIAL PRIMARY KEY,
    network CIDR NOT NULL,
    geoname_id BIGINT,
    registered_country_geoname_id BIGINT,
    represented_country_geoname_id BIGINT,
    is_anonymous_proxy BOOLEAN,
    is_satellite_provider BOOLEAN,
    is_anycast BOOLEAN
);

CREATE TABLE geoip_locations (
    geoname_id BIGINT PRIMARY KEY,
    locale_code VARCHAR(10),
    continent_code VARCHAR(2),
    continent_name VARCHAR(50),
    country_iso_code VARCHAR(2),
    country_name VARCHAR(100),
    is_in_european_union BOOLEAN
);

-- Create index on network for fast IP lookups using GIST
CREATE INDEX idx_geoip_blocks_network ON geoip_blocks USING GIST (network inet_ops);
CREATE INDEX idx_geoip_locations_geoname ON geoip_locations(geoname_id);

-- Auth Logs Table
CREATE TABLE auth_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    hostname VARCHAR(255),
    program VARCHAR(50),
    pid INTEGER,
    log_message TEXT,
    event_type VARCHAR(50),
    username VARCHAR(100),
    source_ip INET,
    port INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_auth_logs_timestamp ON auth_logs(timestamp);
CREATE INDEX idx_auth_logs_source_ip ON auth_logs(source_ip);
CREATE INDEX idx_auth_logs_username ON auth_logs(username);
CREATE INDEX idx_auth_logs_event_type ON auth_logs(event_type);
CREATE INDEX idx_auth_logs_composite ON auth_logs(source_ip, timestamp);

-- Materialized view for GeoIP enriched data
CREATE MATERIALIZED VIEW auth_logs_with_geoip AS
SELECT 
    al.id,
    al.timestamp,
    al.hostname,
    al.program,
    al.event_type,
    al.username,
    al.source_ip,
    al.port,
    gl.country_name,
    gl.country_iso_code,
    gl.continent_name,
    gl.continent_code
FROM auth_logs al
LEFT JOIN geoip_blocks gb ON al.source_ip <<= gb.network
LEFT JOIN geoip_locations gl ON gb.geoname_id = gl.geoname_id;

CREATE INDEX idx_auth_logs_geoip_ip ON auth_logs_with_geoip(source_ip);
CREATE INDEX idx_auth_logs_geoip_country ON auth_logs_with_geoip(country_iso_code);
CREATE INDEX idx_auth_logs_geoip_timestamp ON auth_logs_with_geoip(timestamp);

-- Function to get country for an IP
CREATE OR REPLACE FUNCTION get_country_for_ip(ip_address INET)
RETURNS TABLE(country_name VARCHAR, country_code VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        gl.country_name,
        gl.country_iso_code
    FROM geoip_blocks gb
    JOIN geoip_locations gl ON gb.geoname_id = gl.geoname_id
    WHERE ip_address <<= gb.network
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Import GeoIP data from CSV
COPY geoip_blocks(network, geoname_id, registered_country_geoname_id, 
                  represented_country_geoname_id, is_anonymous_proxy, 
                  is_satellite_provider, is_anycast)
FROM '/geoip/GeoLite2-Country-Blocks-IPv4.csv'
DELIMITER ','
CSV HEADER;

COPY geoip_locations(geoname_id, locale_code, continent_code, continent_name,
                     country_iso_code, country_name, is_in_european_union)
FROM '/geoip/GeoLite2-Country-Locations-en.csv'
DELIMITER ','
CSV HEADER;

-- Analyze tables for better query planning
ANALYZE geoip_blocks;
ANALYZE geoip_locations;
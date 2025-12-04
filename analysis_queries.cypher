// =========================================
// Analysis Queries for Threat Intelligence
// =========================================

// === Query 1: Dominating Attack Groups ===
// Returns attack groups ranked by their activity level
// (number of relationships: tools used, malware deployed, targets)

MATCH (a:Attacker)
OPTIONAL MATCH (a)-[r]-()
WITH a, COUNT(r) as activity_count
RETURN a.name AS AttackGroup, 
       a.aliases AS Aliases,
       activity_count AS TotalActivity
ORDER BY activity_count DESC
LIMIT 10;

// === Query 2: Dominating Tools ===
// Returns tools ranked by usage frequency across threat actors and malware

MATCH (t:Tool)<-[r:USES]-(user)
WITH t, COUNT(r) as usage_count, COLLECT(DISTINCT user.name) as used_by
RETURN t.name AS Tool,
       usage_count AS UsageCount,
       used_by AS UsedBy
ORDER BY usage_count DESC
LIMIT 10;

// === Query 3: Industries Most Affected ===
// Returns industries/organizations ranked by number of attacks targeting them

MATCH (target:Organization)<-[r:TARGETS|ATTACKS|ATTACKED]-(attacker)
WITH target, COUNT(r) as attack_count, COLLECT(DISTINCT attacker.name) as attacked_by
RETURN target.name AS Industry,
       attack_count AS AttackCount,
       attacked_by AS AttackedBy
ORDER BY attack_count DESC
LIMIT 10;

// === Additional Analysis Queries ===

// Most connected entities overall
MATCH (n)
OPTIONAL MATCH (n)-[r]-()
WITH n, labels(n)[0] as label, COUNT(r) as connections
RETURN n.name AS Entity, label AS Type, connections
ORDER BY connections DESC
LIMIT 15;

// Malware families and their relationships
MATCH (m:Malware)-[r]-(connected)
WITH m, type(r) as rel_type, labels(connected)[0] as connected_type, COUNT(*) as count
RETURN m.name AS Malware, 
       rel_type AS Relationship, 
       connected_type AS ConnectedTo, 
       count
ORDER BY m.name, count DESC;

// Vulnerabilities exploited by threat actors
MATCH (a:Attacker)-[:EXPLOITS]->(v:Vulnerability)
RETURN v.name AS Vulnerability, 
       COLLECT(a.name) AS ExploitedBy,
       COUNT(a) AS ThreatActorCount
ORDER BY ThreatActorCount DESC;

// Attack paths: Attacker -> Malware -> Tool chain
MATCH path = (a:Attacker)-[:USES]->(m:Malware)-[:USES]->(t:Tool)
RETURN a.name AS Attacker, 
       m.name AS Malware, 
       t.name AS Tool
LIMIT 20;

// Geographic distribution of threats
MATCH (a:Attacker)-[r:IS_BACKED_BY|LOCATED_IN]->(l:Location)
RETURN l.name AS Location, 
       COLLECT(a.name) AS ThreatActors,
       COUNT(a) AS ActorCount
ORDER BY ActorCount DESC;
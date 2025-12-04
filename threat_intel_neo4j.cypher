// =========================================
// Threat Intelligence Knowledge Graph
// Auto-generated Neo4j Import Script
// =========================================

// Uncomment the following line to clear existing data:
// MATCH (n) DETACH DELETE n;

// === Create Constraints (run once) ===
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Attacker) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Credential) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Event) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Infrastructure) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Location) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Malware) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:MalwareCharacteristicBehavior) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:MalwareCharacteristicCapability) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:MalwareCharacteristicFeature) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Organization) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tool) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.name IS UNIQUE;

// === Create Indexes ===
CREATE INDEX IF NOT EXISTS FOR (n:Attacker) ON (n.name);
CREATE INDEX IF NOT EXISTS FOR (n:Malware) ON (n.name);
CREATE INDEX IF NOT EXISTS FOR (n:Tool) ON (n.name);
CREATE INDEX IF NOT EXISTS FOR (n:Organization) ON (n.name);
CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.name);

// === Create Nodes ===

// --- Attacker nodes ---
MERGE (n:Attacker {name: 'Threat Actor Hades'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];
MERGE (n:Attacker {name: 'Threat Actor Indrik Spider'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];
MERGE (n:Attacker {name: 'Evil Corp'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Evil Corp', 'Threat Actor Conti', 'Threat Actor Indrik Spider', 'Threat Actor DarkSide', 'Threat Actor FIN6'];
MERGE (n:Attacker {name: 'Threat Actor Lead'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];
MERGE (n:Attacker {name: 'Threat Actor FIN6'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor FIN6', 'Threat Actor Evil Corp'];
MERGE (n:Attacker {name: 'Threat Actor Evil Corp'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];
MERGE (n:Attacker {name: 'Threat Actor DarkSide'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Conti', 'Threat Actor Indrik Spider', 'Threat Actor DarkSide'];
MERGE (n:Attacker {name: 'Threat Actor Hive'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor Hive', 'Threat Actor LockBit', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];
MERGE (n:Attacker {name: 'Threat Actor LockBit'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];
MERGE (n:Attacker {name: 'Threat Actor Conti'}) SET n.original_class = 'Attacker', n.aliases = ['Threat Actor LockBit', 'Threat Actor Hive', 'Threat Actor Evil Corp', 'Threat Actor Hades', 'Threat Actor Lead', 'Threat Actor Conti', 'Threat Actor Indrik Spider'];

// --- Credential nodes ---
MERGE (n:Credential {name: 'RDP'}) SET n.original_class = 'Credential', n.aliases = ['RDP'];
MERGE (n:Credential {name: 'VPN'}) SET n.original_class = 'Credential', n.aliases = ['VPN'];

// --- Event nodes ---
MERGE (n:Event {name: 'phishing campaigns'}) SET n.original_class = 'Event', n.aliases = ['phishing campaigns'];
MERGE (n:Event {name: 'call-back phishing'}) SET n.original_class = 'Event', n.aliases = ['call-back phishing'];

// --- Infrastructure nodes ---
MERGE (n:Infrastructure {name: 'DNS'}) SET n.original_class = 'Infrastructure', n.aliases = ['DNS'];
MERGE (n:Infrastructure {name: 'ICMP'}) SET n.original_class = 'Infrastructure', n.aliases = ['ICMP'];
MERGE (n:Infrastructure {name: 'data leak sites'}) SET n.original_class = 'Infrastructure', n.aliases = ['data leak sites'];
MERGE (n:Infrastructure {name: 'MEGA'}) SET n.original_class = 'Infrastructure', n.aliases = ['MEGA'];
MERGE (n:Infrastructure {name: 'Phorpiex/Trik botnet'}) SET n.original_class = 'Infrastructure', n.aliases = ['Phorpiex/Trik botnet'];

// --- Location nodes ---
MERGE (n:Location {name: 'Russia'}) SET n.original_class = 'Location', n.aliases = ['Russia'];

// --- Malware nodes ---
MERGE (n:Malware {name: 'WastedLocker'}) SET n.original_class = 'Malware', n.aliases = ['Malware Phoenix Locker', 'Malware Avaddon', 'Malware WastedLocker', 'WastedLocker ransomware', 'WastedLocker', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades', 'Malware Macaw Locker'];
MERGE (n:Malware {name: 'Phoenix Locker'}) SET n.original_class = 'Malware', n.aliases = ['Phoenix Locker'];
MERGE (n:Malware {name: 'PayloadBIN'}) SET n.original_class = 'Malware', n.aliases = ['Malware PayloadBIN', 'Malware Conti', 'Malware Hive', 'PayloadBIN'];
MERGE (n:Malware {name: 'Dridex'}) SET n.original_class = 'Malware', n.aliases = ['Dridex'];
MERGE (n:Malware {name: 'BitPaymer'}) SET n.original_class = 'Malware', n.aliases = ['BitPaymer'];
MERGE (n:Malware {name: 'Agentemis'}) SET n.original_class = 'Malware', n.aliases = ['Agentemis'];
MERGE (n:Malware {name: 'BleDoor'}) SET n.original_class = 'Malware', n.aliases = ['BleDoor'];
MERGE (n:Malware {name: 'Winnti'}) SET n.original_class = 'Malware', n.aliases = ['Winnti'];
MERGE (n:Malware {name: 'Anchor_DNS'}) SET n.original_class = 'Malware', n.aliases = ['Malware Anchor_DNS', 'Malware Anchor', 'Anchor_DNS'];
MERGE (n:Malware {name: 'LockerGoga'}) SET n.original_class = 'Malware', n.aliases = ['LockerGoga'];
MERGE (n:Malware {name: 'Ryuk'}) SET n.original_class = 'Malware', n.aliases = ['Ryuk'];
MERGE (n:Malware {name: 'Malware TrickBot'}) SET n.original_class = 'Malware', n.aliases = ['Malware TrickBot', 'TrickBot'];
MERGE (n:Malware {name: 'JavaScript Downloader'}) SET n.original_class = 'Malware', n.aliases = ['JavaScript Downloader'];
MERGE (n:Malware {name: 'Ryuk ransomware'}) SET n.original_class = 'Malware', n.aliases = ['Malware Phoenix Locker', 'Malware Avaddon', 'Ryuk ransomware', 'Malware WastedLocker', 'WastedLocker ransomware', 'Malware Conti', 'Malware LockBit', 'Malware DarkSide', 'Malware Macaw Locker'];
MERGE (n:Malware {name: 'Conti ransomware'}) SET n.original_class = 'Malware', n.aliases = ['Malware SocGholish', 'Malware Hive', 'Malware PayloadBIN', 'Malware Conti', 'Conti ransomware', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware SocGholish'}) SET n.original_class = 'Malware', n.aliases = ['Malware SocGholish', 'Malware Hive', 'Malware PayloadBIN', 'Malware Conti', 'Conti ransomware', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'WastedLocker ransomware'}) SET n.original_class = 'Malware', n.aliases = ['Malware Phoenix Locker', 'Malware Avaddon', 'Ryuk ransomware', 'Malware WastedLocker', 'WastedLocker ransomware', 'Malware Conti', 'Malware LockBit', 'Malware DarkSide', 'Malware Macaw Locker'];
MERGE (n:Malware {name: 'Malware WastedLocker'}) SET n.original_class = 'Malware', n.aliases = ['Malware Avaddon', 'Malware WastedLocker', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware Hades'}) SET n.original_class = 'Malware', n.aliases = ['Malware Avaddon', 'Malware WastedLocker', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware Phoenix Locker'}) SET n.original_class = 'Malware', n.aliases = ['Malware Phoenix Locker', 'Malware Avaddon', 'Ryuk ransomware', 'Malware WastedLocker', 'WastedLocker ransomware', 'Malware Conti', 'Malware LockBit', 'Malware DarkSide', 'Malware Macaw Locker'];
MERGE (n:Malware {name: 'Malware PayloadBIN'}) SET n.original_class = 'Malware', n.aliases = ['Malware SocGholish', 'Malware Hive', 'Malware PayloadBIN', 'Malware Conti', 'Conti ransomware', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware Macaw Locker'}) SET n.original_class = 'Malware', n.aliases = ['Malware Phoenix Locker', 'Malware Avaddon', 'Ryuk ransomware', 'Malware WastedLocker', 'WastedLocker ransomware', 'Malware Conti', 'Malware LockBit', 'Malware DarkSide', 'Malware Macaw Locker'];
MERGE (n:Malware {name: 'Hades'}) SET n.original_class = 'Malware', n.aliases = ['Hades'];
MERGE (n:Malware {name: 'SocGholish'}) SET n.original_class = 'Malware', n.aliases = ['Malware SocGholish', 'SocGholish'];
MERGE (n:Malware {name: 'RbDoor'}) SET n.original_class = 'Malware', n.aliases = ['RbDoor'];
MERGE (n:Malware {name: 'Malware Anchor'}) SET n.original_class = 'Malware', n.aliases = ['Malware Hive', 'Malware Anchor', 'Malware PayloadBIN', 'Malware Conti', 'Malware Hades'];
MERGE (n:Malware {name: 'TrickBot'}) SET n.original_class = 'Malware', n.aliases = ['Malware TrickBot', 'TrickBot'];
MERGE (n:Malware {name: 'Malware Anchor_DNS'}) SET n.original_class = 'Malware', n.aliases = ['Malware Anchor_DNS', 'Malware Anchor', 'Anchor_DNS'];
MERGE (n:Malware {name: 'Anchor'}) SET n.original_class = 'Malware', n.aliases = ['Anchor'];
MERGE (n:Malware {name: 'Malware DarkSide'}) SET n.original_class = 'Malware', n.aliases = ['Malware Avaddon', 'Malware WastedLocker', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware Hive'}) SET n.original_class = 'Malware', n.aliases = ['Malware SocGholish', 'Malware Hive', 'Malware PayloadBIN', 'Malware Conti', 'Conti ransomware', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware LockBit'}) SET n.original_class = 'Malware', n.aliases = ['Malware Avaddon', 'Malware WastedLocker', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware Conti'}) SET n.original_class = 'Malware', n.aliases = ['Malware SocGholish', 'Malware Hive', 'Malware PayloadBIN', 'Malware Conti', 'Conti ransomware', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];
MERGE (n:Malware {name: 'Malware Avaddon'}) SET n.original_class = 'Malware', n.aliases = ['Malware Avaddon', 'Malware WastedLocker', 'Malware LockBit', 'Malware DarkSide', 'Malware Hades'];

// --- MalwareCharacteristicBehavior nodes ---
MERGE (n:MalwareCharacteristicBehavior {name: 'indirect API calls'}) SET n.original_class = 'Malware Characteristic:Behavior', n.aliases = ['indirect API calls'];

// --- MalwareCharacteristicCapability nodes ---
MERGE (n:MalwareCharacteristicCapability {name: 'Salsa20'}) SET n.original_class = 'Malware Characteristic:Capability', n.aliases = ['Salsa20'];
MERGE (n:MalwareCharacteristicCapability {name: 'RSA-1024'}) SET n.original_class = 'Malware Characteristic:Capability', n.aliases = ['RSA-1024'];
MERGE (n:MalwareCharacteristicCapability {name: 'double-extortion'}) SET n.original_class = 'Malware Characteristic:Capability', n.aliases = ['double-extortion'];

// --- MalwareCharacteristicFeature nodes ---
MERGE (n:MalwareCharacteristicFeature {name: 'custom token for execution'}) SET n.original_class = 'Malware Characteristic:Feature', n.aliases = ['custom token for execution'];

// --- Organization nodes ---
MERGE (n:Organization {name: 'Colonial Pipeline'}) SET n.original_class = 'Organization', n.aliases = ['Colonial Pipeline'];
MERGE (n:Organization {name: 'medical, educational non-profits'}) SET n.original_class = 'Organization', n.aliases = ['medical, educational non-profits'];
MERGE (n:Organization {name: 'Healthcare'}) SET n.original_class = 'Organization', n.aliases = ['Healthcare'];
MERGE (n:Organization {name: 'Transportation'}) SET n.original_class = 'Organization', n.aliases = ['Transportation'];
MERGE (n:Organization {name: 'Technology'}) SET n.original_class = 'Organization', n.aliases = ['Technology'];
MERGE (n:Organization {name: 'Insurance'}) SET n.original_class = 'Organization', n.aliases = ['Insurance'];
MERGE (n:Organization {name: 'Manufacturing'}) SET n.original_class = 'Organization', n.aliases = ['Manufacturing'];
MERGE (n:Organization {name: 'Business Services'}) SET n.original_class = 'Organization', n.aliases = ['Business Services'];
MERGE (n:Organization {name: 'small and medium sized business'}) SET n.original_class = 'Organization', n.aliases = ['small and medium sized business'];
MERGE (n:Organization {name: 'Education'}) SET n.original_class = 'Organization', n.aliases = ['Education'];
MERGE (n:Organization {name: 'First Responders'}) SET n.original_class = 'Organization', n.aliases = ['First Responders'];

// --- Tool nodes ---
MERGE (n:Tool {name: 'Cobalt Strike'}) SET n.original_class = 'Tool', n.aliases = ['CobaltStrike', 'Cobalt Strike'];
MERGE (n:Tool {name: 'Mimikatz'}) SET n.original_class = 'Tool', n.aliases = ['Mimikatz'];
MERGE (n:Tool {name: 'PsExec'}) SET n.original_class = 'Tool', n.aliases = ['PsExec'];
MERGE (n:Tool {name: 'AdFind'}) SET n.original_class = 'Tool', n.aliases = ['AdFind'];
MERGE (n:Tool {name: 'Empire'}) SET n.original_class = 'Tool', n.aliases = ['Empire'];
MERGE (n:Tool {name: 'CobaltStrike'}) SET n.original_class = 'Tool', n.aliases = ['CobaltStrike', 'Cobalt Strike'];
MERGE (n:Tool {name: 'cobeacon'}) SET n.original_class = 'Tool', n.aliases = ['cobeacon'];
MERGE (n:Tool {name: 'Meterpreter'}) SET n.original_class = 'Tool', n.aliases = ['Meterpreter'];
MERGE (n:Tool {name: '7-Zip'}) SET n.original_class = 'Tool', n.aliases = ['WinRAR', '7-Zip'];
MERGE (n:Tool {name: 'Rclone'}) SET n.original_class = 'Tool', n.aliases = ['Rclone'];
MERGE (n:Tool {name: 'StealBit'}) SET n.original_class = 'Tool', n.aliases = ['StealBit'];
MERGE (n:Tool {name: 'WinRAR'}) SET n.original_class = 'Tool', n.aliases = ['WinRAR', '7-Zip'];
MERGE (n:Tool {name: 'AnyDesk'}) SET n.original_class = 'Tool', n.aliases = ['AnyDesk'];
MERGE (n:Tool {name: 'LSASS credential dumping'}) SET n.original_class = 'Tool', n.aliases = ['LSASS credential dumping'];
MERGE (n:Tool {name: 'Kerberoasting'}) SET n.original_class = 'Tool', n.aliases = ['Kerberoasting'];
MERGE (n:Tool {name: 'PowerShell scripts'}) SET n.original_class = 'Tool', n.aliases = ['PowerShell scripts'];

// --- Vulnerability nodes ---
MERGE (n:Vulnerability {name: 'CVE-2018-13379'}) SET n.original_class = 'Vulnerability', n.aliases = ['CVE-2018-13379'];
MERGE (n:Vulnerability {name: 'CVE-2020-1472'}) SET n.original_class = 'Vulnerability', n.aliases = ['CVE-2020-1472'];
MERGE (n:Vulnerability {name: 'CVE-2021-34527'}) SET n.original_class = 'Vulnerability', n.aliases = ['CVE-2021-34527'];

// === Create Relationships ===

// --- ATTACKED relationships ---
MATCH (a:Attacker {name: 'Threat Actor DarkSide'}), (b:Organization {name: 'Colonial Pipeline'}) MERGE (a)-[r:ATTACKED]->(b) SET r.original_relation = 'attacked';

// --- ATTACKS relationships ---
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'small and medium sized business'}) MERGE (a)-[r:ATTACKS]->(b) SET r.original_relation = 'attacks';

// --- AVOIDS relationships ---
MATCH (a:Attacker {name: 'Threat Actor DarkSide'}), (b:Organization {name: 'medical, educational non-profits'}) MERGE (a)-[r:AVOIDS]->(b) SET r.original_relation = 'avoids';

// --- COMMUNICATES_OVER relationships ---
MATCH (a:Malware {name: 'Malware Anchor_DNS'}), (b:Infrastructure {name: 'DNS'}) MERGE (a)-[r:COMMUNICATES_OVER]->(b) SET r.original_relation = 'communicates over';
MATCH (a:Malware {name: 'Malware Anchor_DNS'}), (b:Infrastructure {name: 'ICMP'}) MERGE (a)-[r:COMMUNICATES_OVER]->(b) SET r.original_relation = 'communicates over';

// --- DELIVERS relationships ---
MATCH (a:Malware {name: 'Malware TrickBot'}), (b:Malware {name: 'Ryuk ransomware'}) MERGE (a)-[r:DELIVERS]->(b) SET r.original_relation = 'delivers';
MATCH (a:Malware {name: 'Malware TrickBot'}), (b:Malware {name: 'Conti ransomware'}) MERGE (a)-[r:DELIVERS]->(b) SET r.original_relation = 'delivers';
MATCH (a:Malware {name: 'Malware SocGholish'}), (b:Malware {name: 'WastedLocker ransomware'}) MERGE (a)-[r:DELIVERS]->(b) SET r.original_relation = 'delivers';
MATCH (a:Malware {name: 'Malware DarkSide'}), (b:Infrastructure {name: 'data leak sites'}) MERGE (a)-[r:DELIVERS]->(b) SET r.original_relation = 'delivers';

// --- DEPLOYED_BY relationships ---
MATCH (a:Malware {name: 'Malware Conti'}), (b:Malware {name: 'TrickBot'}) MERGE (a)-[r:DEPLOYED_BY]->(b) SET r.original_relation = 'deployed by';

// --- DEPLOYS relationships ---
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Malware {name: 'Anchor_DNS'}) MERGE (a)-[r:DEPLOYS]->(b) SET r.original_relation = 'deploys';

// --- ENGAGES_IN relationships ---
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Event {name: 'call-back phishing'}) MERGE (a)-[r:ENGAGES_IN]->(b) SET r.original_relation = 'engages in';

// --- EXPLOITS relationships ---
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Vulnerability {name: 'CVE-2018-13379'}) MERGE (a)-[r:EXPLOITS]->(b) SET r.original_relation = 'exploits';
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Vulnerability {name: 'CVE-2020-1472'}) MERGE (a)-[r:EXPLOITS]->(b) SET r.original_relation = 'exploits';
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Vulnerability {name: 'CVE-2021-34527'}) MERGE (a)-[r:EXPLOITS]->(b) SET r.original_relation = 'exploits';

// --- IS_ALSO_KNOWN_AS relationships ---
MATCH (a:Attacker {name: 'Threat Actor Indrik Spider'}), (b:Attacker {name: 'Evil Corp'}) MERGE (a)-[r:IS_ALSO_KNOWN_AS]->(b) SET r.original_relation = 'is also known as';

// --- IS_BACKED_BY relationships ---
MATCH (a:Attacker {name: 'Threat Actor Hades'}), (b:Location {name: 'Russia'}) MERGE (a)-[r:IS_BACKED_BY]->(b) SET r.original_relation = 'is backed by';

// --- IS_DELIVERED_BY relationships ---
MATCH (a:Malware {name: 'Malware TrickBot'}), (b:Event {name: 'phishing campaigns'}) MERGE (a)-[r:IS_DELIVERED_BY]->(b) SET r.original_relation = 'is delivered by';
MATCH (a:Malware {name: 'Malware Avaddon'}), (b:Infrastructure {name: 'Phorpiex/Trik botnet'}) MERGE (a)-[r:IS_DELIVERED_BY]->(b) SET r.original_relation = 'is delivered by';

// --- IS_DEPLOYED_BY relationships ---
MATCH (a:Malware {name: 'Malware Hades'}), (b:Attacker {name: 'Evil Corp'}) MERGE (a)-[r:IS_DEPLOYED_BY]->(b) SET r.original_relation = 'is deployed by';
MATCH (a:Malware {name: 'Malware Phoenix Locker'}), (b:Attacker {name: 'Evil Corp'}) MERGE (a)-[r:IS_DEPLOYED_BY]->(b) SET r.original_relation = 'is deployed by';
MATCH (a:Malware {name: 'Malware Anchor'}), (b:Malware {name: 'TrickBot'}) MERGE (a)-[r:IS_DEPLOYED_BY]->(b) SET r.original_relation = 'is deployed by';

// --- IS_DERIVED_FROM relationships ---
MATCH (a:Malware {name: 'Malware PayloadBIN'}), (b:Malware {name: 'Phoenix Locker'}) MERGE (a)-[r:IS_DERIVED_FROM]->(b) SET r.original_relation = 'is derived from';
MATCH (a:Malware {name: 'Malware Macaw Locker'}), (b:Malware {name: 'Hades'}) MERGE (a)-[r:IS_DERIVED_FROM]->(b) SET r.original_relation = 'is derived from';

// --- IS_USED_BY relationships ---
MATCH (a:Malware {name: 'Malware SocGholish'}), (b:Attacker {name: 'Evil Corp'}) MERGE (a)-[r:IS_USED_BY]->(b) SET r.original_relation = 'is used by';
MATCH (a:Malware {name: 'Malware WastedLocker'}), (b:Attacker {name: 'Evil Corp'}) MERGE (a)-[r:IS_USED_BY]->(b) SET r.original_relation = 'is used by';

// --- IS_VARIANT_OF relationships ---
MATCH (a:Malware {name: 'Malware Anchor_DNS'}), (b:Malware {name: 'Anchor'}) MERGE (a)-[r:IS_VARIANT_OF]->(b) SET r.original_relation = 'is variant of';

// --- PREDICTED_IS relationships ---
MATCH (a:Attacker {name: 'Threat Actor Hades'}), (b:Attacker {name: 'Threat Actor Conti'}) MERGE (a)-[r:PREDICTED_IS]->(b) SET r.original_relation = 'predicted:is';

// --- REQUIRES relationships ---
MATCH (a:Malware {name: 'Malware Macaw Locker'}), (b:MalwareCharacteristicFeature {name: 'custom token for execution'}) MERGE (a)-[r:REQUIRES]->(b) SET r.original_relation = 'requires';

// --- TARGETS relationships ---
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'Healthcare'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'Transportation'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'Technology'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'Insurance'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'Manufacturing'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Hive'}), (b:Organization {name: 'Business Services'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor LockBit'}), (b:Organization {name: 'Healthcare'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor LockBit'}), (b:Organization {name: 'Education'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Organization {name: 'Healthcare'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Organization {name: 'First Responders'}) MERGE (a)-[r:TARGETS]->(b) SET r.original_relation = 'targets';

// --- USES relationships ---
MATCH (a:Attacker {name: 'Threat Actor Hades'}), (b:Malware {name: 'WastedLocker'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Hades'}), (b:Malware {name: 'Phoenix Locker'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Hades'}), (b:Malware {name: 'PayloadBIN'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Indrik Spider'}), (b:Malware {name: 'Dridex'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Indrik Spider'}), (b:Malware {name: 'BitPaymer'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Indrik Spider'}), (b:Malware {name: 'WastedLocker'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Indrik Spider'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Malware {name: 'Agentemis'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Malware {name: 'BleDoor'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Malware {name: 'Winnti'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Malware {name: 'Anchor_DNS'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Tool {name: 'Mimikatz'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Tool {name: 'PsExec'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Malware {name: 'LockerGoga'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Malware {name: 'Ryuk'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Tool {name: 'AdFind'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware TrickBot'}), (b:Malware {name: 'JavaScript Downloader'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware TrickBot'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware TrickBot'}), (b:Tool {name: 'Empire'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Macaw Locker'}), (b:MalwareCharacteristicBehavior {name: 'indirect API calls'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Evil Corp'}), (b:Malware {name: 'SocGholish'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Evil Corp'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Malware {name: 'RbDoor'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Tool {name: 'CobaltStrike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Lead'}), (b:Tool {name: 'cobeacon'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Malware {name: 'Anchor'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor FIN6'}), (b:Tool {name: 'Meterpreter'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware DarkSide'}), (b:MalwareCharacteristicCapability {name: 'Salsa20'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware DarkSide'}), (b:MalwareCharacteristicCapability {name: 'RSA-1024'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware DarkSide'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Hive'}), (b:MalwareCharacteristicCapability {name: 'double-extortion'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Hive'}), (b:Tool {name: '7-Zip'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Hive'}), (b:Infrastructure {name: 'MEGA'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Hive'}), (b:Tool {name: 'Rclone'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware LockBit'}), (b:Tool {name: 'StealBit'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware LockBit'}), (b:Tool {name: 'WinRAR'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware LockBit'}), (b:Tool {name: 'AnyDesk'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware LockBit'}), (b:Tool {name: 'PsExec'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware LockBit'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor LockBit'}), (b:Credential {name: 'RDP'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor LockBit'}), (b:Credential {name: 'VPN'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Conti'}), (b:Tool {name: 'Cobalt Strike'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Conti'}), (b:Tool {name: 'Mimikatz'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Conti'}), (b:Tool {name: 'PsExec'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Tool {name: 'LSASS credential dumping'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Attacker {name: 'Threat Actor Conti'}), (b:Tool {name: 'Kerberoasting'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';
MATCH (a:Malware {name: 'Malware Avaddon'}), (b:Tool {name: 'PowerShell scripts'}) MERGE (a)-[r:USES]->(b) SET r.original_relation = 'uses';

// === Import Complete ===
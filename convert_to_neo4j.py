#!/usr/bin/env python3
"""
Script to convert threat intelligence JSON to Neo4j database.
Generates Cypher statements and can optionally execute them against a Neo4j instance.

Usage:
    python convert_to_neo4j.py                    # Generate Cypher file only
    python convert_to_neo4j.py --execute          # Generate and execute (requires neo4j driver)
    python convert_to_neo4j.py --uri bolt://localhost:7687 --user neo4j --password password --execute
"""

import json
import re
import sys
import argparse
from collections import defaultdict


def sanitize_for_cypher(text):
    """Sanitize text for Cypher compatibility."""
    if text is None:
        return ""
    text = str(text)
    # Escape backslashes first, then single quotes
    text = text.replace('\\', '\\\\')
    text = text.replace("'", "\\'")
    return text


def normalize_label(entity_class):
    """Normalize entity class to valid Neo4j label."""
    if entity_class is None:
        return "Unknown"
    # Handle composite classes like "Malware Characteristic:Behavior"
    # Replace special chars with underscore, CamelCase
    label = re.sub(r'[^a-zA-Z0-9]', '_', str(entity_class))
    # Remove consecutive underscores
    label = re.sub(r'_+', '_', label)
    # Remove leading/trailing underscores
    label = label.strip('_')
    # Convert to CamelCase
    parts = label.split('_')
    return ''.join(word.capitalize() for word in parts if word)


def normalize_relationship(relation):
    """Normalize relationship name for Neo4j."""
    if relation is None:
        return "RELATED_TO"
    # Uppercase, replace spaces and special chars with underscore
    rel = re.sub(r'[^a-zA-Z0-9]', '_', str(relation).upper())
    rel = re.sub(r'_+', '_', rel)
    return rel.strip('_')


def create_node_key(text, entity_class):
    """Create a unique key for node deduplication."""
    normalized = re.sub(r'[^a-zA-Z0-9_\s-]', '', str(text))
    normalized = normalized.strip().lower()
    return f"{normalize_label(entity_class)}_{normalized}"


def load_json_data(filepath):
    """Load and parse the JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_entities_and_relations(data):
    """Extract unique entities and relationships from the JSON data."""
    entities = {}  # node_key -> {name, label, properties}
    relationships = []  # list of (source_key, target_key, rel_type, properties)
    
    # Process ET section (typed_triplets) - primary source
    if 'ET' in data and 'typed_triplets' in data['ET']:
        for triplet in data['ET']['typed_triplets']:
            subject = triplet.get('subject', {})
            obj = triplet.get('object', {})
            relation = triplet.get('relation', 'related_to')
            
            # Extract subject entity
            subj_text = subject.get('text', '')
            subj_class = subject.get('class', 'Unknown')
            if subj_text:
                subj_key = create_node_key(subj_text, subj_class)
                if subj_key not in entities:
                    entities[subj_key] = {
                        'name': subj_text,
                        'label': normalize_label(subj_class),
                        'original_class': subj_class,
                        'aliases': set([subj_text])
                    }
                else:
                    entities[subj_key]['aliases'].add(subj_text)
            
            # Extract object entity
            obj_text = obj.get('text', '')
            obj_class = obj.get('class', 'Unknown')
            if obj_text:
                obj_key = create_node_key(obj_text, obj_class)
                if obj_key not in entities:
                    entities[obj_key] = {
                        'name': obj_text,
                        'label': normalize_label(obj_class),
                        'original_class': obj_class,
                        'aliases': set([obj_text])
                    }
                else:
                    entities[obj_key]['aliases'].add(obj_text)
            
            # Create relationship
            if subj_text and obj_text:
                relationships.append({
                    'source': subj_key,
                    'target': obj_key,
                    'type': normalize_relationship(relation),
                    'original_relation': relation
                })
    
    # Process LP section (Link Prediction) for predicted relationships
    if 'LP' in data and 'predicted_links' in data['LP']:
        for link in data['LP']['predicted_links']:
            subject = link.get('subject', {})
            obj = link.get('object', {})
            relation = link.get('relation', 'predicted_link')
            
            # Extract subject
            subj_text = subject.get('mention_text', '')
            subj_class = subject.get('mention_class', 'Unknown')
            if subj_text:
                subj_key = create_node_key(subj_text, subj_class)
                if subj_key not in entities:
                    entities[subj_key] = {
                        'name': subj_text,
                        'label': normalize_label(subj_class),
                        'original_class': subj_class,
                        'aliases': set([subj_text])
                    }
            
            # Extract object
            obj_text = obj.get('mention_text', '')
            obj_class = obj.get('mention_class', subject.get('mention_class', 'Unknown'))
            if obj_text:
                obj_key = create_node_key(obj_text, obj_class)
                if obj_key not in entities:
                    entities[obj_key] = {
                        'name': obj_text,
                        'label': normalize_label(obj_class),
                        'original_class': obj_class,
                        'aliases': set([obj_text])
                    }
            
            # Create relationship (marked as predicted)
            if subj_text and obj_text:
                relationships.append({
                    'source': subj_key,
                    'target': obj_key,
                    'type': f"PREDICTED_{normalize_relationship(relation)}",
                    'original_relation': f"predicted:{relation}"
                })
    
    # Process EA section for additional entity information and aliases
    if 'EA' in data and 'aligned_triplets' in data['EA']:
        for triplet in data['EA']['aligned_triplets']:
            subject = triplet.get('subject', {})
            obj = triplet.get('object', {})
            
            # Update subject with merged aliases
            subj_text = subject.get('mention_text', '')
            subj_class = subject.get('mention_class', 'Unknown')
            subj_entity_text = subject.get('entity_text', subj_text)
            merged = subject.get('mention_merged', [])
            
            if subj_text:
                subj_key = create_node_key(subj_text, subj_class)
                if subj_key in entities:
                    entities[subj_key]['aliases'].add(subj_entity_text)
                    for alias in merged:
                        entities[subj_key]['aliases'].add(alias)
            
            # Update object with merged aliases
            obj_text = obj.get('mention_text', '')
            obj_class = obj.get('mention_class', 'Unknown')
            obj_entity_text = obj.get('entity_text', obj_text)
            merged = obj.get('mention_merged', [])
            
            if obj_text:
                obj_key = create_node_key(obj_text, obj_class)
                if obj_key in entities:
                    entities[obj_key]['aliases'].add(obj_entity_text)
                    for alias in merged:
                        entities[obj_key]['aliases'].add(alias)
    
    # Convert alias sets to lists
    for key in entities:
        entities[key]['aliases'] = list(entities[key]['aliases'])
    
    # Remove duplicate relationships
    seen_rels = set()
    unique_relationships = []
    for rel in relationships:
        rel_key = (rel['source'], rel['target'], rel['type'])
        if rel_key not in seen_rels:
            seen_rels.add(rel_key)
            unique_relationships.append(rel)
    
    return entities, unique_relationships


def generate_cypher_statements(entities, relationships):
    """Generate Cypher statements for Neo4j import."""
    statements = []
    
    # Header comment
    statements.append("// =========================================")
    statements.append("// Threat Intelligence Knowledge Graph")
    statements.append("// Auto-generated Neo4j Import Script")
    statements.append("// =========================================")
    statements.append("")
    
    # Clear existing data (optional, commented out by default)
    statements.append("// Uncomment the following line to clear existing data:")
    statements.append("// MATCH (n) DETACH DELETE n;")
    statements.append("")
    
    # Create constraints for each label type
    statements.append("// === Create Constraints (run once) ===")
    labels = set(e['label'] for e in entities.values())
    for label in sorted(labels):
        statements.append(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.name IS UNIQUE;")
    statements.append("")
    
    # Create indexes for common properties
    statements.append("// === Create Indexes ===")
    statements.append("CREATE INDEX IF NOT EXISTS FOR (n:Attacker) ON (n.name);")
    statements.append("CREATE INDEX IF NOT EXISTS FOR (n:Malware) ON (n.name);")
    statements.append("CREATE INDEX IF NOT EXISTS FOR (n:Tool) ON (n.name);")
    statements.append("CREATE INDEX IF NOT EXISTS FOR (n:Organization) ON (n.name);")
    statements.append("CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.name);")
    statements.append("")
    
    # Create nodes
    statements.append("// === Create Nodes ===")
    
    # Group entities by label for batch creation
    entities_by_label = defaultdict(list)
    for key, entity in entities.items():
        entities_by_label[entity['label']].append(entity)
    
    for label in sorted(entities_by_label.keys()):
        statements.append(f"\n// --- {label} nodes ---")
        for entity in entities_by_label[label]:
            name = sanitize_for_cypher(entity['name'])
            original_class = sanitize_for_cypher(entity['original_class'])
            aliases = [sanitize_for_cypher(a) for a in entity['aliases']]
            aliases_str = "', '".join(aliases)
            
            stmt = f"MERGE (n:{label} {{name: '{name}'}}) "
            stmt += f"SET n.original_class = '{original_class}', "
            stmt += f"n.aliases = ['{aliases_str}'];"
            statements.append(stmt)
    
    statements.append("")
    
    # Create relationships
    statements.append("// === Create Relationships ===")
    
    # Group relationships by type
    rels_by_type = defaultdict(list)
    for rel in relationships:
        rels_by_type[rel['type']].append(rel)
    
    for rel_type in sorted(rels_by_type.keys()):
        statements.append(f"\n// --- {rel_type} relationships ---")
        for rel in rels_by_type[rel_type]:
            source_entity = entities.get(rel['source'])
            target_entity = entities.get(rel['target'])
            
            if source_entity and target_entity:
                source_name = sanitize_for_cypher(source_entity['name'])
                source_label = source_entity['label']
                target_name = sanitize_for_cypher(target_entity['name'])
                target_label = target_entity['label']
                original_rel = sanitize_for_cypher(rel['original_relation'])
                
                stmt = f"MATCH (a:{source_label} {{name: '{source_name}'}}), "
                stmt += f"(b:{target_label} {{name: '{target_name}'}}) "
                stmt += f"MERGE (a)-[r:{rel_type}]->(b) "
                stmt += f"SET r.original_relation = '{original_rel}';"
                statements.append(stmt)
    
    statements.append("")
    statements.append("// === Import Complete ===")
    
    return statements


def generate_analysis_queries():
    """Generate Cypher queries for analysis."""
    queries = []
    
    queries.append("// =========================================")
    queries.append("// Analysis Queries for Threat Intelligence")
    queries.append("// =========================================")
    queries.append("")
    
    # Query 1: Dominating Attack Groups
    queries.append("// === Query 1: Dominating Attack Groups ===")
    queries.append("// Returns attack groups ranked by their activity level")
    queries.append("// (number of relationships: tools used, malware deployed, targets)")
    queries.append("")
    queries.append("""MATCH (a:Attacker)
OPTIONAL MATCH (a)-[r]-()
WITH a, COUNT(r) as activity_count
RETURN a.name AS AttackGroup, 
       a.aliases AS Aliases,
       activity_count AS TotalActivity
ORDER BY activity_count DESC
LIMIT 10;""")
    queries.append("")
    
    # Query 2: Dominating Tools
    queries.append("// === Query 2: Dominating Tools ===")
    queries.append("// Returns tools ranked by usage frequency across threat actors and malware")
    queries.append("")
    queries.append("""MATCH (t:Tool)<-[r:USES]-(user)
WITH t, COUNT(r) as usage_count, COLLECT(DISTINCT user.name) as used_by
RETURN t.name AS Tool,
       usage_count AS UsageCount,
       used_by AS UsedBy
ORDER BY usage_count DESC
LIMIT 10;""")
    queries.append("")
    
    # Query 3: Industries Most Affected
    queries.append("// === Query 3: Industries Most Affected ===")
    queries.append("// Returns industries/organizations ranked by number of attacks targeting them")
    queries.append("")
    queries.append("""MATCH (target:Organization)<-[r:TARGETS|ATTACKS|ATTACKED]-(attacker)
WITH target, COUNT(r) as attack_count, COLLECT(DISTINCT attacker.name) as attacked_by
RETURN target.name AS Industry,
       attack_count AS AttackCount,
       attacked_by AS AttackedBy
ORDER BY attack_count DESC
LIMIT 10;""")
    queries.append("")
    
    # Additional useful queries
    queries.append("// === Additional Analysis Queries ===")
    queries.append("")
    
    queries.append("// Most connected entities overall")
    queries.append("""MATCH (n)
OPTIONAL MATCH (n)-[r]-()
WITH n, labels(n)[0] as label, COUNT(r) as connections
RETURN n.name AS Entity, label AS Type, connections
ORDER BY connections DESC
LIMIT 15;""")
    queries.append("")
    
    queries.append("// Malware families and their relationships")
    queries.append("""MATCH (m:Malware)-[r]-(connected)
WITH m, type(r) as rel_type, labels(connected)[0] as connected_type, COUNT(*) as count
RETURN m.name AS Malware, 
       rel_type AS Relationship, 
       connected_type AS ConnectedTo, 
       count
ORDER BY m.name, count DESC;""")
    queries.append("")
    
    queries.append("// Vulnerabilities exploited by threat actors")
    queries.append("""MATCH (a:Attacker)-[:EXPLOITS]->(v:Vulnerability)
RETURN v.name AS Vulnerability, 
       COLLECT(a.name) AS ExploitedBy,
       COUNT(a) AS ThreatActorCount
ORDER BY ThreatActorCount DESC;""")
    queries.append("")
    
    queries.append("// Attack paths: Attacker -> Malware -> Tool chain")
    queries.append("""MATCH path = (a:Attacker)-[:USES]->(m:Malware)-[:USES]->(t:Tool)
RETURN a.name AS Attacker, 
       m.name AS Malware, 
       t.name AS Tool
LIMIT 20;""")
    queries.append("")
    
    queries.append("// Geographic distribution of threats")
    queries.append("""MATCH (a:Attacker)-[r:IS_BACKED_BY|LOCATED_IN]->(l:Location)
RETURN l.name AS Location, 
       COLLECT(a.name) AS ThreatActors,
       COUNT(a) AS ActorCount
ORDER BY ActorCount DESC;""")
    
    return queries


def write_cypher_file(statements, output_path):
    """Write Cypher statements to file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(statements))


def execute_cypher(statements, uri, user, password):
    """Execute Cypher statements against Neo4j database."""
    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("ERROR: neo4j driver not installed. Install with: pip install neo4j")
        return False
    
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    try:
        with driver.session() as session:
            # Filter out comments and empty lines
            executable = [s for s in statements 
                         if s.strip() and not s.strip().startswith('//')]
            
            total = len(executable)
            for i, stmt in enumerate(executable, 1):
                try:
                    session.run(stmt)
                    if i % 50 == 0:
                        print(f"Progress: {i}/{total} statements executed")
                except Exception as e:
                    print(f"Warning: Failed to execute statement: {stmt[:80]}...")
                    print(f"  Error: {e}")
            
            print(f"Successfully executed {total} statements")
            return True
    finally:
        driver.close()


def main():
    parser = argparse.ArgumentParser(
        description='Convert threat intelligence JSON to Neo4j database'
    )
    parser.add_argument('--input', '-i', 
                        default='/mnt/user-data/uploads/000.json',
                        help='Input JSON file path')
    parser.add_argument('--output', '-o', 
                        default='/mnt/user-data/outputs/threat_intel_neo4j.cypher',
                        help='Output Cypher file path')
    parser.add_argument('--queries', '-q',
                        default='/mnt/user-data/outputs/analysis_queries.cypher',
                        help='Output analysis queries file path')
    parser.add_argument('--execute', '-e', action='store_true',
                        help='Execute statements against Neo4j')
    parser.add_argument('--uri', default='bolt://localhost:7687',
                        help='Neo4j connection URI')
    parser.add_argument('--user', '-u', default='neo4j',
                        help='Neo4j username')
    parser.add_argument('--password', '-p', default='password',
                        help='Neo4j password')
    
    args = parser.parse_args()
    
    print(f"Loading JSON data from: {args.input}")
    data = load_json_data(args.input)
    
    print("Extracting entities and relationships...")
    entities, relationships = extract_entities_and_relations(data)
    
    print(f"Found {len(entities)} unique entities")
    print(f"Found {len(relationships)} unique relationships")
    
    # Print distribution
    label_counts = defaultdict(int)
    for entity in entities.values():
        label_counts[entity['label']] += 1
    
    print("\nEntity distribution by type:")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"  {label}: {count}")
    
    print("\nGenerating Cypher statements...")
    statements = generate_cypher_statements(entities, relationships)
    
    print(f"Writing import script to: {args.output}")
    write_cypher_file(statements, args.output)
    
    print("Generating analysis queries...")
    queries = generate_analysis_queries()
    print(f"Writing analysis queries to: {args.queries}")
    write_cypher_file(queries, args.queries)
    
    if args.execute:
        print(f"\nExecuting against Neo4j at {args.uri}...")
        execute_cypher(statements, args.uri, args.user, args.password)
    
    print("\n=== Conversion Complete ===")
    print(f"Import script: {args.output}")
    print(f"Analysis queries: {args.queries}")
    print("\nTo import into Neo4j:")
    print("  1. Start Neo4j database")
    print("  2. Open Neo4j Browser or cypher-shell")
    print(f"  3. Run: :source {args.output}")
    print("     Or copy-paste the contents")
    print(f"  4. Run analysis queries from: {args.queries}")


if __name__ == '__main__':
    main()

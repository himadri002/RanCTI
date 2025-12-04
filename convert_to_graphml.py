#!/usr/bin/env python3
"""
Script to convert threat intelligence JSON to GraphML format.
Processes the ET (Entity Typing) section with typed_triplets to create a knowledge graph.
"""

import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from collections import defaultdict
import sys
import re


def sanitize_for_xml(text):
    """Sanitize text for XML compatibility."""
    if text is None:
        return ""
    text = str(text)
    # Replace problematic characters
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&apos;')
    return text


def normalize_class(entity_class):
    """Normalize entity class names for consistency."""
    if entity_class is None:
        return "Unknown"
    # Handle composite classes like "Malware Characteristic:Behavior"
    if ":" in entity_class:
        return entity_class.replace(":", "_").replace(" ", "_")
    return entity_class.replace(" ", "_")


def create_node_id(text, entity_class):
    """Create a unique, consistent node ID from text and class."""
    # Normalize text: lowercase, remove special chars, replace spaces with underscores
    normalized = re.sub(r'[^a-zA-Z0-9_\s-]', '', str(text))
    normalized = normalized.strip().replace(' ', '_').lower()
    class_prefix = normalize_class(entity_class).lower()
    return f"{class_prefix}_{normalized}"


def load_json_data(filepath):
    """Load and parse the JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_nodes_and_edges(data):
    """Extract unique nodes and edges from the JSON data."""
    nodes = {}  # node_id -> {text, class, aliases}
    edges = []  # list of (source_id, target_id, relation)
    
    # Process ET section (typed_triplets) - primary source
    if 'ET' in data and 'typed_triplets' in data['ET']:
        for triplet in data['ET']['typed_triplets']:
            subject = triplet.get('subject', {})
            obj = triplet.get('object', {})
            relation = triplet.get('relation', 'related_to')
            
            # Extract subject node
            subj_text = subject.get('text', '')
            subj_class = subject.get('class', 'Unknown')
            if subj_text:
                subj_id = create_node_id(subj_text, subj_class)
                if subj_id not in nodes:
                    nodes[subj_id] = {
                        'text': subj_text,
                        'class': subj_class,
                        'aliases': set()
                    }
                nodes[subj_id]['aliases'].add(subj_text)
            
            # Extract object node
            obj_text = obj.get('text', '')
            obj_class = obj.get('class', 'Unknown')
            if obj_text:
                obj_id = create_node_id(obj_text, obj_class)
                if obj_id not in nodes:
                    nodes[obj_id] = {
                        'text': obj_text,
                        'class': obj_class,
                        'aliases': set()
                    }
                nodes[obj_id]['aliases'].add(obj_text)
            
            # Create edge
            if subj_text and obj_text:
                edges.append((subj_id, obj_id, relation))
    
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
                subj_id = create_node_id(subj_text, subj_class)
                if subj_id not in nodes:
                    nodes[subj_id] = {
                        'text': subj_text,
                        'class': subj_class,
                        'aliases': set()
                    }
                nodes[subj_id]['aliases'].add(subj_text)
            
            # Extract object
            obj_text = obj.get('mention_text', '')
            obj_class = obj.get('mention_class', subject.get('mention_class', 'Unknown'))
            if obj_text:
                obj_id = create_node_id(obj_text, obj_class)
                if obj_id not in nodes:
                    nodes[obj_id] = {
                        'text': obj_text,
                        'class': obj_class,
                        'aliases': set()
                    }
                nodes[obj_id]['aliases'].add(obj_text)
            
            # Create edge (mark as predicted)
            if subj_text and obj_text:
                edges.append((subj_id, obj_id, f"PREDICTED:{relation}"))
    
    # Also process EA section for additional entity information
    if 'EA' in data and 'aligned_triplets' in data['EA']:
        for triplet in data['EA']['aligned_triplets']:
            subject = triplet.get('subject', {})
            obj = triplet.get('object', {})
            relation = triplet.get('relation', 'related_to')
            
            # Extract subject with entity info
            subj_text = subject.get('mention_text', '')
            subj_class = subject.get('mention_class', 'Unknown')
            subj_entity_text = subject.get('entity_text', subj_text)
            merged = subject.get('mention_merged', [])
            
            if subj_text:
                subj_id = create_node_id(subj_text, subj_class)
                if subj_id not in nodes:
                    nodes[subj_id] = {
                        'text': subj_text,
                        'class': subj_class,
                        'aliases': set()
                    }
                nodes[subj_id]['aliases'].add(subj_text)
                nodes[subj_id]['aliases'].add(subj_entity_text)
                for alias in merged:
                    nodes[subj_id]['aliases'].add(alias)
            
            # Extract object with entity info
            obj_text = obj.get('mention_text', '')
            obj_class = obj.get('mention_class', 'Unknown')
            obj_entity_text = obj.get('entity_text', obj_text)
            merged = obj.get('mention_merged', [])
            
            if obj_text:
                obj_id = create_node_id(obj_text, obj_class)
                if obj_id not in nodes:
                    nodes[obj_id] = {
                        'text': obj_text,
                        'class': obj_class,
                        'aliases': set()
                    }
                nodes[obj_id]['aliases'].add(obj_text)
                nodes[obj_id]['aliases'].add(obj_entity_text)
                for alias in merged:
                    nodes[obj_id]['aliases'].add(alias)
    
    # Convert alias sets to lists for JSON serialization
    for node_id in nodes:
        nodes[node_id]['aliases'] = list(nodes[node_id]['aliases'])
    
    # Remove duplicate edges
    unique_edges = list(set(edges))
    
    return nodes, unique_edges


def create_graphml(nodes, edges, output_path):
    """Create GraphML file from nodes and edges."""
    
    # Create root element with namespaces
    graphml = ET.Element('graphml')
    graphml.set('xmlns', 'http://graphml.graphdrawing.org/xmlns')
    graphml.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
    graphml.set('xsi:schemaLocation', 
                'http://graphml.graphdrawing.org/xmlns '
                'http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd')
    
    # Define node attributes (keys)
    key_label = ET.SubElement(graphml, 'key')
    key_label.set('id', 'd0')
    key_label.set('for', 'node')
    key_label.set('attr.name', 'label')
    key_label.set('attr.type', 'string')
    
    key_class = ET.SubElement(graphml, 'key')
    key_class.set('id', 'd1')
    key_class.set('for', 'node')
    key_class.set('attr.name', 'entity_class')
    key_class.set('attr.type', 'string')
    
    key_aliases = ET.SubElement(graphml, 'key')
    key_aliases.set('id', 'd2')
    key_aliases.set('for', 'node')
    key_aliases.set('attr.name', 'aliases')
    key_aliases.set('attr.type', 'string')
    
    # Define edge attributes
    key_relation = ET.SubElement(graphml, 'key')
    key_relation.set('id', 'd3')
    key_relation.set('for', 'edge')
    key_relation.set('attr.name', 'relation')
    key_relation.set('attr.type', 'string')
    
    # Create graph
    graph = ET.SubElement(graphml, 'graph')
    graph.set('id', 'ThreatIntelGraph')
    graph.set('edgedefault', 'directed')
    
    # Add nodes
    for node_id, node_data in nodes.items():
        node = ET.SubElement(graph, 'node')
        node.set('id', node_id)
        
        # Add label
        data_label = ET.SubElement(node, 'data')
        data_label.set('key', 'd0')
        data_label.text = sanitize_for_xml(node_data['text'])
        
        # Add class
        data_class = ET.SubElement(node, 'data')
        data_class.set('key', 'd1')
        data_class.text = sanitize_for_xml(node_data['class'])
        
        # Add aliases
        data_aliases = ET.SubElement(node, 'data')
        data_aliases.set('key', 'd2')
        data_aliases.text = sanitize_for_xml('|'.join(node_data['aliases']))
    
    # Add edges
    for idx, (source, target, relation) in enumerate(edges):
        edge = ET.SubElement(graph, 'edge')
        edge.set('id', f'e{idx}')
        edge.set('source', source)
        edge.set('target', target)
        
        data_rel = ET.SubElement(edge, 'data')
        data_rel.set('key', 'd3')
        data_rel.text = sanitize_for_xml(relation)
    
    # Create pretty-printed XML
    xml_str = ET.tostring(graphml, encoding='unicode')
    dom = minidom.parseString(xml_str)
    pretty_xml = dom.toprettyxml(indent='  ')
    
    # Remove extra blank lines
    lines = [line for line in pretty_xml.split('\n') if line.strip()]
    pretty_xml = '\n'.join(lines)
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(pretty_xml)
    
    return len(nodes), len(edges)


def main():
    """Main function to orchestrate the conversion."""
    input_file = '/mnt/user-data/uploads/000.json'
    output_file = '/mnt/user-data/outputs/threat_intel_graph.graphml'
    
    # Allow command line override
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    print(f"Loading JSON data from: {input_file}")
    data = load_json_data(input_file)
    
    print("Extracting nodes and edges...")
    nodes, edges = extract_nodes_and_edges(data)
    
    print(f"Creating GraphML file: {output_file}")
    num_nodes, num_edges = create_graphml(nodes, edges, output_file)
    
    print(f"\n=== Conversion Complete ===")
    print(f"Total nodes: {num_nodes}")
    print(f"Total edges: {num_edges}")
    print(f"Output file: {output_file}")
    
    # Print node class distribution
    class_counts = defaultdict(int)
    for node_data in nodes.values():
        class_counts[node_data['class']] += 1
    
    print(f"\nNode distribution by class:")
    for cls, count in sorted(class_counts.items(), key=lambda x: -x[1]):
        print(f"  {cls}: {count}")


if __name__ == '__main__':
    main()

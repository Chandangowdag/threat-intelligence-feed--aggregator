# Threat Intelligence Feed Aggregator
# A comprehensive cybersecurity threat intelligence platform

import sqlite3
import feedparser
import requests
import re
import json
import sqlite3
import gradio as gr
from datetime import datetime, timedelta
import hashlib
import urllib.parse
from typing import List, Dict, Optional, Tuple
import logging
from dataclasses import dataclass, asdict
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelItem:
    """Data structure for threat intelligence items"""
    id: str
    title: str
    description: str
    source: str
    published: str
    link: str
    iocs: Dict[str, List[str]]
    summary: str = ""
    severity: str = "unknown"
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

class IOCExtractor:
    """Extract Indicators of Compromise from text using regex patterns"""
    
    def __init__(self):
        self.patterns = {
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domains': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'urls': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            'md5_hashes': r'\b[a-fA-F0-9]{32}\b',
            'sha1_hashes': r'\b[a-fA-F0-9]{40}\b',
            'sha256_hashes': r'\b[a-fA-F0-9]{64}\b',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'cve_ids': r'CVE-\d{4}-\d{4,7}',
            'file_paths': r'(?:[A-Za-z]:\\|/)(?:[^\\/:*?"<>|\r\n]+[\\\/])*[^\\/:*?"<>|\r\n]*',
        }
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract all IOCs from given text"""
        iocs = {}
        
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            # Remove duplicates and filter out common false positives
            filtered_matches = list(set(self._filter_false_positives(matches, ioc_type)))
            if filtered_matches:
                iocs[ioc_type] = filtered_matches
        
        return iocs
    
    def _filter_false_positives(self, matches: List[str], ioc_type: str) -> List[str]:
        """Filter out common false positives"""
        if ioc_type == 'ip_addresses':
            # Filter out private IP ranges and invalid IPs
            filtered = []
            for ip in matches:
                octets = ip.split('.')
                if len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets):
                    # Skip private IP ranges for threat intel purposes
                    first_octet = int(octets[0])
                    if not (first_octet in [10, 127] or 
                           (first_octet == 172 and 16 <= int(octets[1]) <= 31) or
                           (first_octet == 192 and int(octets[1]) == 168)):
                        filtered.append(ip)
            return filtered
        
        elif ioc_type == 'domains':
            # Filter out common domains that aren't threats
            common_domains = {'github.com', 'twitter.com', 'facebook.com', 'google.com', 
                            'microsoft.com', 'apple.com', 'amazon.com', 'example.com',
                            'localhost', 'www.w3.org'}
            return [d for d in matches if d.lower() not in common_domains]
        
        return matches

class ThreatIntelDatabase:
    """SQLite database for storing threat intelligence data"""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                source TEXT,
                published TEXT,
                link TEXT,
                iocs TEXT,
                summary TEXT,
                severity TEXT,
                tags TEXT,
                created_at TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feed_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                url TEXT,
                feed_type TEXT,
                last_updated TEXT,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_threat_intel(self, item: ThreatIntelItem):
        """Save threat intelligence item to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_intel 
            (id, title, description, source, published, link, iocs, summary, severity, tags, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item.id,
            item.title,
            item.description,
            item.source,
            item.published,
            item.link,
            json.dumps(item.iocs),
            item.summary,
            item.severity,
            json.dumps(item.tags),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 50) -> List[ThreatIntelItem]:
        """Get recent threat intelligence items"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threat_intel 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        items = []
        for row in rows:
            item = ThreatIntelItem(
                id=row[0],
                title=row[1],
                description=row[2],
                source=row[3],
                published=row[4],
                link=row[5],
                iocs=json.loads(row[6]) if row[6] else {},
                summary=row[7] or "",
                severity=row[8] or "unknown",
                tags=json.loads(row[9]) if row[9] else []
            )
            items.append(item)
        
        return items
    
    def search_threats(self, query: str, limit: int = 50) -> List[ThreatIntelItem]:
        """Search threats by query"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threat_intel 
            WHERE title LIKE ? OR description LIKE ? OR summary LIKE ?
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (f'%{query}%', f'%{query}%', f'%{query}%', limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        items = []
        for row in rows:
            item = ThreatIntelItem(
                id=row[0],
                title=row[1],
                description=row[2],
                source=row[3],
                published=row[4],
                link=row[5],
                iocs=json.loads(row[6]) if row[6] else {},
                summary=row[7] or "",
                severity=row[8] or "unknown",
                tags=json.loads(row[9]) if row[9] else []
            )
            items.append(item)
        
        return items

class FeedCollector:
    """Collect threat intelligence from RSS/Atom feeds and other sources"""
    
    def __init__(self, db: ThreatIntelDatabase, ioc_extractor: IOCExtractor):
        self.db = db
        self.ioc_extractor = ioc_extractor
        self.default_feeds = [
            {
                'name': 'US-CERT CISA',
                'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
                'type': 'rss'
            },
            {
                'name': 'SANS Internet Storm Center',
                'url': 'https://isc.sans.edu/rssfeed.xml',
                'type': 'rss'
            },
            {
                'name': 'Krebs on Security',
                'url': 'https://krebsonsecurity.com/feed/',
                'type': 'rss'
            },
            {
                'name': 'Malware Bytes Labs',
                'url': 'https://blog.malwarebytes.com/feed/',
                'type': 'rss'
            },
            {
                'name': 'Threat Post',
                'url': 'https://threatpost.com/feed/',
                'type': 'rss'
            }
        ]
    
    def collect_from_feed(self, feed_url: str, feed_name: str) -> List[ThreatIntelItem]:
        """Collect threat intelligence from a single RSS/Atom feed"""
        items = []
        
        try:
            logger.info(f"Fetching feed: {feed_name}")
            feed = feedparser.parse(feed_url)
            
            for entry in feed.entries[:20]:  # Limit to 20 most recent items
                # Generate unique ID
                item_id = hashlib.md5(f"{entry.link}_{entry.title}".encode()).hexdigest()
                
                # Extract text content
                content = getattr(entry, 'summary', '') or getattr(entry, 'description', '')
                content += f" {entry.title}"
                
                # Extract IOCs
                iocs = self.ioc_extractor.extract_iocs(content)
                
                # Create threat intel item
                item = ThreatIntelItem(
                    id=item_id,
                    title=entry.title,
                    description=getattr(entry, 'summary', '')[:500] + "..." if len(getattr(entry, 'summary', '')) > 500 else getattr(entry, 'summary', ''),
                    source=feed_name,
                    published=getattr(entry, 'published', datetime.now().isoformat()),
                    link=entry.link,
                    iocs=iocs,
                    tags=self._extract_tags(entry.title + " " + content)
                )
                
                items.append(item)
            
            logger.info(f"Collected {len(items)} items from {feed_name}")
            
        except Exception as e:
            logger.error(f"Error collecting from {feed_name}: {str(e)}")
        
        return items
    
    def _extract_tags(self, text: str) -> List[str]:
        """Extract relevant tags from text"""
        tags = []
        threat_keywords = {
            'malware', 'ransomware', 'phishing', 'apt', 'vulnerability', 'exploit',
            'botnet', 'trojan', 'backdoor', 'rootkit', 'spyware', 'adware',
            'ddos', 'mitm', 'injection', 'xss', 'csrf', 'rce', 'lfi', 'rfi',
            'zero-day', 'patch', 'update', 'breach', 'leak', 'stolen', 'compromised'
        }
        
        text_lower = text.lower()
        for keyword in threat_keywords:
            if keyword in text_lower:
                tags.append(keyword)
        
        return tags
    
    def collect_all_feeds(self) -> List[ThreatIntelItem]:
        """Collect from all configured feeds"""
        all_items = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_feed = {
                executor.submit(self.collect_from_feed, feed['url'], feed['name']): feed
                for feed in self.default_feeds
            }
            
            for future in as_completed(future_to_feed):
                try:
                    items = future.result()
                    all_items.extend(items)
                except Exception as e:
                    logger.error(f"Error in feed collection: {str(e)}")
        
        return all_items

class AIAnalyzer:
    """AI-powered analysis and summarization (Mock implementation)"""
    
    def __init__(self):
        # In a real implementation, this would connect to Ollama or another LLM service
        self.mock_mode = True
    
    def generate_summary(self, threat_item: ThreatIntelItem) -> str:
        """Generate AI summary of threat intelligence item"""
        if self.mock_mode:
            return self._generate_mock_summary(threat_item)
        
        # Real implementation would use Ollama/LLM API
        # Example: ollama_client.generate("llama2", prompt=self._create_prompt(threat_item))
        pass
    
    def _generate_mock_summary(self, threat_item: ThreatIntelItem) -> str:
        """Generate mock summary based on content analysis"""
        title = threat_item.title.lower()
        description = threat_item.description.lower()
        
        # Determine threat type
        threat_type = "Unknown"
        if any(word in title + description for word in ['malware', 'trojan', 'virus']):
            threat_type = "Malware"
        elif any(word in title + description for word in ['phishing', 'email', 'campaign']):
            threat_type = "Phishing Campaign"
        elif any(word in title + description for word in ['vulnerability', 'cve', 'exploit']):
            threat_type = "Vulnerability"
        elif any(word in title + description for word in ['ransomware', 'encryption']):
            threat_type = "Ransomware"
        elif any(word in title + description for word in ['apt', 'advanced', 'persistent']):
            threat_type = "APT Activity"
        
        # Determine severity
        severity = "Medium"
        if any(word in title + description for word in ['critical', 'severe', 'high', 'urgent']):
            severity = "High"
        elif any(word in title + description for word in ['low', 'minor', 'informational']):
            severity = "Low"
        
        # Generate summary
        summary = f"🔍 **Threat Type**: {threat_type}\n"
        summary += f"⚠️ **Severity**: {severity}\n"
        summary += f"📊 **IOCs Found**: {sum(len(iocs) for iocs in threat_item.iocs.values())}\n"
        
        if threat_item.iocs:
            summary += "**Key Indicators**:\n"
            for ioc_type, iocs in threat_item.iocs.items():
                if iocs:
                    summary += f"• {ioc_type.replace('_', ' ').title()}: {len(iocs)} found\n"
        
        return summary
    
    def assess_severity(self, threat_item: ThreatIntelItem) -> str:
        """Assess threat severity"""
        content = (threat_item.title + " " + threat_item.description).lower()
        
        high_severity_keywords = ['critical', 'severe', 'urgent', 'zero-day', 'worm', 'ransomware']
        medium_severity_keywords = ['vulnerability', 'exploit', 'malware', 'phishing']
        
        if any(keyword in content for keyword in high_severity_keywords):
            return "High"
        elif any(keyword in content for keyword in medium_severity_keywords):
            return "Medium"
        else:
            return "Low"

class ThreatIntelAggregator:
    """Main aggregator class that coordinates all components"""
    
    def __init__(self):
        self.db = ThreatIntelDatabase()
        self.ioc_extractor = IOCExtractor()
        self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
        self.ai_analyzer = AIAnalyzer()
        self.last_update = None
        self.is_updating = False
    
    def refresh_feeds(self, progress_callback=None):
        """Refresh all threat intelligence feeds"""
        if self.is_updating:
            return "Update already in progress..."
        
        self.is_updating = True
        
        try:
            logger.info("Starting feed refresh...")
            
            # Collect new items
            new_items = self.feed_collector.collect_all_feeds()
            
            # Process with AI analysis
            processed_count = 0
            for item in new_items:
                # Generate summary
                item.summary = self.ai_analyzer.generate_summary(item)
                
                # Assess severity
                item.severity = self.ai_analyzer.assess_severity(item)
                
                # Save to database
                self.db.save_threat_intel(item)
                processed_count += 1
                
                if progress_callback:
                    progress_callback(processed_count, len(new_items))
            
            self.last_update = datetime.now()
            logger.info(f"Feed refresh completed. Processed {processed_count} items.")
            
            return f"Successfully updated {processed_count} threat intelligence items."
            
        except Exception as e:
            logger.error(f"Error during feed refresh: {str(e)}")
            return f"Error during update: {str(e)}"
        
        finally:
            self.is_updating = False
    
    def get_dashboard_data(self) -> Dict:
        """Get data for dashboard display"""
        recent_threats = self.db.get_recent_threats(50)
        
        # Calculate statistics
        stats = {
            'total_threats': len(recent_threats),
            'high_severity': len([t for t in recent_threats if t.severity == "High"]),
            'medium_severity': len([t for t in recent_threats if t.severity == "Medium"]),
            'low_severity': len([t for t in recent_threats if t.severity == "Low"]),
            'total_iocs': sum(sum(len(iocs) for iocs in t.iocs.values()) for t in recent_threats),
            'last_update': self.last_update.strftime("%Y-%m-%d %H:%M:%S") if self.last_update else "Never"
        }
        
        return {
            'threats': recent_threats,
            'stats': stats
        }
    
    def search_threats(self, query: str) -> List[ThreatIntelItem]:
        """Search threats by query"""
        return self.db.search_threats(query)
    
    def export_iocs(self, format_type: str = "json") -> str:
        """Export IOCs in specified format"""
        threats = self.db.get_recent_threats(100)
        all_iocs = {}
        
        for threat in threats:
            for ioc_type, iocs in threat.iocs.items():
                if ioc_type not in all_iocs:
                    all_iocs[ioc_type] = []
                all_iocs[ioc_type].extend(iocs)
        
        # Remove duplicates
        for ioc_type in all_iocs:
            all_iocs[ioc_type] = list(set(all_iocs[ioc_type]))
        
        if format_type == "json":
            return json.dumps(all_iocs, indent=2)
        elif format_type == "csv":
            csv_content = "IOC_Type,IOC_Value\n"
            for ioc_type, iocs in all_iocs.items():
                for ioc in iocs:
                    csv_content += f"{ioc_type},{ioc}\n"
            return csv_content
        
        return str(all_iocs)

# Initialize the aggregator
aggregator = ThreatIntelAggregator()

def create_gradio_interface():
    """Create the Gradio web interface"""
    
    def refresh_feeds():
        """Refresh feeds and return status"""
        return aggregator.refresh_feeds()
    
    def get_threat_list():
        """Get formatted threat list for display"""
        data = aggregator.get_dashboard_data()
        threats = data['threats']
        stats = data['stats']
        
        # Create statistics display
        stats_html = f"""
        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <div style="background: #f0f0f0; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #333;">Total Threats</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #2196F3;">{stats['total_threats']}</p>
            </div>
            <div style="background: #ffebee; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #333;">High Severity</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #f44336;">{stats['high_severity']}</p>
            </div>
            <div style="background: #fff3e0; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #333;">Medium Severity</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #ff9800;">{stats['medium_severity']}</p>
            </div>
            <div style="background: #e8f5e8; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #333;">Total IOCs</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #4caf50;">{stats['total_iocs']}</p>
            </div>
        </div>
        <p><strong>Last Update:</strong> {stats['last_update']}</p>
        """
        
        # Create threat list
        threat_html = ""
        for threat in threats[:10]:  # Show top 10
            severity_color = {
                "High": "#f44336",
                "Medium": "#ff9800", 
                "Low": "#4caf50"
            }.get(threat.severity, "#666")
            
            ioc_summary = ", ".join([f"{k}: {len(v)}" for k, v in threat.iocs.items() if v])
            
            summary_formatted = threat.summary.replace('\n', '<br>')
            threat_html += f"""
            <div style="border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 8px; background: white;">
                <h4 style="margin: 0 0 10px 0; color: #333;">
                    <span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 10px;">{threat.severity}</span>
                    {threat.title}
                </h4>
                <p style="margin: 5px 0; color: #666;"><strong>Source:</strong> {threat.source}</p>
                <p style="margin: 5px 0; color: #666;"><strong>Published:</strong> {threat.published}</p>
                <p style="margin: 10px 0;">{threat.description}</p>
                {f'<p style="margin: 5px 0; color: #666;"><strong>IOCs:</strong> {ioc_summary}</p>' if ioc_summary else ''}
                <div style="margin-top: 10px; padding: 10px; background: #f9f9f9; border-radius: 4px;">
                    <strong>AI Summary:</strong><br>
                    {summary_formatted}
                </div>
                <p style="margin: 10px 0 0 0;"><a href="{threat.link}" target="_blank" style="color: #2196F3;">View Full Article</a></p>
            </div>
               """
               
        
        return stats_html + threat_html
    
    def search_threats(query):
        """Search threats and return formatted results"""
        if not query.strip():
            return "Please enter a search query."
        
        results = aggregator.search_threats(query)
        
        if not results:
            return f"No threats found matching '{query}'"
        
        search_html = f"<h3>Search Results for '{query}' ({len(results)} found)</h3>"
        
        for threat in results[:10]:  # Show top 10 results
            severity_color = {
                "High": "#f44336",
                "Medium": "#ff9800", 
                "Low": "#4caf50"
            }.get(threat.severity, "#666")
            
            ioc_summary = ", ".join([f"{k}: {len(v)}" for k, v in threat.iocs.items() if v])
            
            summary_formatted = threat.summary.replace('\n', '<br>')
            search_html += f"""
            <div style="border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 8px; background: white;">
                <h4 style="margin: 0 0 10px 0; color: #333;">
                    <span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 10px;">{threat.severity}</span>
                    {threat.title}
                </h4>
                <p style="margin: 5px 0; color: #666;"><strong>Source:</strong> {threat.source}</p>
                <p style="margin: 10px 0;">{threat.description}</p>
                {f'<p style="margin: 5px 0; color: #666;"><strong>IOCs:</strong> {ioc_summary}</p>' if ioc_summary else ''}
                <div style="margin-top: 10px; padding: 10px; background: #f9f9f9; border-radius: 4px;">
                    <strong>AI Summary:</strong><br>
                    {summary_formatted}
                </div>
                <p style="margin: 10px 0 0 0;"><a href="{threat.link}" target="_blank" style="color: #2196F3;">View Full Article</a></p>
            </div>
            """
        
        return search_html
    
    def export_iocs_handler(format_type):
        """Handle IOC export"""
        return aggregator.export_iocs(format_type)
    
    # Create Gradio interface
    with gr.Blocks(title="Threat Intelligence Aggregator", theme=gr.themes.Soft()) as demo:
        gr.Markdown("# 🛡️ Threat Intelligence Feed Aggregator")
        gr.Markdown("**AI-Powered Cybersecurity Threat Intelligence Platform**")
        
        with gr.Tabs():
            with gr.TabItem("📊 Dashboard"):
                gr.Markdown("## Real-time Threat Intelligence Dashboard")
                
                with gr.Row():
                    refresh_btn = gr.Button("🔄 Refresh Feeds", variant="primary")
                    refresh_status = gr.Textbox(label="Status", interactive=False)
                
                dashboard_display = gr.HTML(get_threat_list())
                
                refresh_btn.click(
                    fn=lambda: (refresh_feeds(), get_threat_list()),
                    outputs=[refresh_status, dashboard_display]
                )
            
            with gr.TabItem("🔍 Search"):
                gr.Markdown("## Search Threat Intelligence")
                
                with gr.Row():
                    search_query = gr.Textbox(label="Search Query", placeholder="Enter keywords, CVE IDs, domains, etc.")
                    search_btn = gr.Button("Search", variant="primary")
                
                search_results = gr.HTML()
                
                search_btn.click(
                    fn=search_threats,
                    inputs=[search_query],
                    outputs=[search_results]
                )
            
            with gr.TabItem("📋 IOC Export"):
                gr.Markdown("## Export Indicators of Compromise")
                
                with gr.Row():
                    export_format = gr.Dropdown(
                        choices=["json", "csv"],
                        label="Export Format",
                        value="json"
                    )
                    export_btn = gr.Button("Export IOCs", variant="primary")
                
                export_output = gr.Textbox(
                    label="Exported IOCs",
                    lines=20,
                    max_lines=30
                )
                
                export_btn.click(
                    fn=export_iocs_handler,
                    inputs=[export_format],
                    outputs=[export_output]
                )
            
            with gr.TabItem("ℹ️ About"):
                gr.Markdown("""
                ## About This Tool
                
                The Threat Intelligence Feed Aggregator is an AI-powered platform designed to help security professionals:
                
                - **Aggregate** threat intelligence from multiple RSS/Atom feeds
                - **Extract** Indicators of Compromise (IOCs) automatically
                - **Analyze** threats using AI-powered summarization
                - **Search** through collected threat data
                - **Export** IOCs in multiple formats
                
                ### Features
                
                - 🔄 **Real-time Feed Collection**: Automatically fetches from curated security feeds
                - 🤖 **AI-Powered Analysis**: Generates summaries and assesses threat severity
                - 🔍 **Advanced Search**: Search across titles, descriptions, and summaries
                - 📊 **IOC Extraction**: Automatically extracts IPs, domains, hashes, CVEs, and more
                - 📋 **Export Capabilities**: Export IOCs in JSON or CSV format
                - 🛡️ **Security Focused**: Built specifically for cybersecurity professionals
                
                ### Data Sources
                
                - US-CERT CISA Advisories
                - SANS Internet Storm Center
                - Krebs on Security
                - Malware Bytes Labs
                - Threat Post
                
                ### Technical Stack
                
                - **Backend**: Python with SQLite database
                - **IOC Extraction**: Advanced regex pattern matching
                - **AI Analysis**: Mock implementation (ready for Ollama integration)
                - **Web Interface**: Gradio for intuitive user experience
                - **Data Processing**: Multi-threaded feed collection
                
                ### Usage Instructions
                
                1. **Dashboard**: View real-time threat intelligence and statistics
                2. **Refresh Feeds**: Click "Refresh Feeds" to update threat data
                3. **Search**: Use the search tab to find specific threats
                4. **Export**: Download IOCs in JSON or CSV format for integration
                
                ### Integration Ready
                
                This tool is designed to integrate with:
                - SIEM platforms
                - Security orchestration tools
                - Threat hunting workflows
                - Incident response playbooks
                
                ---
                
                **Built for the Cybersecurity Community** 🔒
                """)
    
    # Auto-refresh dashboard every 5 minutes
    def auto_refresh():
        """Auto-refresh dashboard data"""
        while True:
            time.sleep(300)  # 5 minutes
            try:
                dashboard_display.update(get_threat_list())
            except:
                pass
    
    # Start auto-refresh in background
    refresh_thread = threading.Thread(target=auto_refresh, daemon=True)
    refresh_thread.start()
    
    return demo

# Run the application
if __name__ == "__main__":
    # Initialize with some sample data if database is empty
    demo = create_gradio_interface()
    
    # Launch the interface
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=True,
        debug=False
    )
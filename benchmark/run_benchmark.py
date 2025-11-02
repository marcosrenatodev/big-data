#!/usr/bin/env python3
import time
import psycopg2
from elasticsearch import Elasticsearch
import statistics
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Connection details
PG_CONN = {
    'host': 'localhost',
    'database': 'logdb',
    'user': 'loguser',
    'password': 'logpass',
    'port': 5432
}

ES_HOST = 'http://localhost:9200'

class Benchmark:
    def __init__(self):
        self.pg_conn = psycopg2.connect(**PG_CONN)
        # Fix for Elasticsearch client compatibility
        self.es_client = Elasticsearch(
            [ES_HOST],
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True
        )
        self.results = []

    def print_results(self):
    print("\n{:<15} {:<25} {:<10} {:<10} {:<10} {:<12}".format(
        "Database", "Query Name", "Avg (ms)", "Min (ms)", "Max (ms)", "Results"))
    print("-" * 85)
    for r in self.results:
        print("{:<15} {:<25} {:<10} {:<10} {:<10} {:<12}".format(
            r['database'], r['query'], r['avg_ms'], r['min_ms'], r['max_ms'], r['result_count']
        ))
    
    def run_pg_query(self, name, query, params=None):
        """Run PostgreSQL query and measure time."""
        times = []
        cur = self.pg_conn.cursor()
        
        # Warm-up run
        cur.execute(query, params)
        cur.fetchall()
        
        # Actual benchmark runs
        for i in range(5):
            start = time.time()
            cur.execute(query, params)
            results = cur.fetchall()
            end = time.time()
            times.append((end - start) * 1000)  # Convert to ms
        
        cur.close()
        
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        
        self.results.append({
            'database': 'PostgreSQL',
            'query': name,
            'avg_ms': round(avg_time, 2),
            'min_ms': round(min_time, 2),
            'max_ms': round(max_time, 2),
            'result_count': len(results)
        })
        
        print(f"PG - {name}: {avg_time:.2f}ms (min: {min_time:.2f}, max: {max_time:.2f})")
    
    def run_es_query(self, name, index, body):
        """Run Elasticsearch query and measure time."""
        times = []
        
        try:
            # Warm-up run
            self.es_client.search(index=index, body=body)
            
            # Actual benchmark runs
            for i in range(5):
                start = time.time()
                response = self.es_client.search(index=index, body=body)
                end = time.time()
                times.append((end - start) * 1000)  # Convert to ms
            
            avg_time = statistics.mean(times)
            min_time = min(times)
            max_time = max(times)
            
            # Handle different response formats
            if isinstance(response['hits']['total'], dict):
                total_hits = response['hits']['total']['value']
            else:
                total_hits = response['hits']['total']
            
            self.results.append({
                'database': 'Elasticsearch',
                'query': name,
                'avg_ms': round(avg_time, 2),
                'min_ms': round(min_time, 2),
                'max_ms': round(max_time, 2),
                'result_count': total_hits
            })
            
            print(f"ES - {name}: {avg_time:.2f}ms (min: {min_time:.2f}, max: {max_time:.2f})")
            
        except Exception as e:
            print(f"ES - {name}: ERROR - {str(e)}")
            self.results.append({
                'database': 'Elasticsearch',
                'query': name,
                'avg_ms': 0,
                'min_ms': 0,
                'max_ms': 0,
                'result_count': 0
            })
    
    def test_simple_queries(self):
        """Test simple queries."""
        print("\n=== Simple Queries ===\n")
        
        # Query 1: Count all failed login attempts
        print("Query 1: Count all failed login attempts")
        
        self.run_pg_query(
            "Count failed logins",
            "SELECT COUNT(*) FROM auth_logs WHERE event_type = 'failed_password'"
        )
        
        self.run_es_query(
            "Count failed logins",
            "auth-logs-*",
            {
                "query": {
                    "term": {"event_type.keyword": "failed_password"}
                },
                "size": 0,
                "track_total_hits": True
            }
        )
        
        # Query 2: Find all attempts from a specific IP
        print("\nQuery 2: Find all attempts from specific IP")
        
        self.run_pg_query(
            "Attempts from IP",
            "SELECT * FROM auth_logs WHERE source_ip = %s LIMIT 100",
            ('152.32.247.71',)
        )
        
        self.run_es_query(
            "Attempts from IP",
            "auth-logs-*",
            {
                "query": {
                    "term": {"source_ip": "152.32.247.71"}
                },
                "size": 100
            }
        )
        
        # Query 3: Top 10 attacking IPs
        print("\nQuery 3: Top 10 attacking IPs")
        
        self.run_pg_query(
            "Top 10 IPs",
            """
            SELECT source_ip, COUNT(*) as attempt_count
            FROM auth_logs
            WHERE event_type IN ('failed_password', 'auth_failure')
            GROUP BY source_ip
            ORDER BY attempt_count DESC
            LIMIT 10
            """
        )
        
        self.run_es_query(
            "Top 10 IPs",
            "auth-logs-*",
            {
                "query": {
                    "terms": {"event_type.keyword": ["failed_password", "auth_failure"]}
                },
                "aggs": {
                    "top_ips": {
                        "terms": {
                            "field": "source_ip",
                            "size": 10,
                            "order": {"_count": "desc"}
                        }
                    }
                },
                "size": 0
            }
        )
    
    def test_complex_queries(self):
        """Test complex queries with GeoIP."""
        print("\n=== Complex Queries ===\n")
        
        # Query 1: Attacks by country
        print("Query 1: Attacks by country")
        
        self.run_pg_query(
            "Attacks by country",
            """
            SELECT country_name, COUNT(*) as attack_count
            FROM auth_logs_with_geoip
            WHERE event_type IN ('failed_password', 'auth_failure')
            AND country_name IS NOT NULL
            GROUP BY country_name
            ORDER BY attack_count DESC
            LIMIT 20
            """
        )
        
        self.run_es_query(
            "Attacks by country",
            "auth-logs-*",
            {
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"event_type.keyword": ["failed_password", "auth_failure"]}},
                            {"exists": {"field": "geoip.country_name"}}
                        ]
                    }
                },
                "aggs": {
                    "by_country": {
                        "terms": {
                            "field": "geoip.country_name.keyword",
                            "size": 20
                        }
                    }
                },
                "size": 0
            }
        )
        
        # Query 2: Time-based aggregation (attacks per hour)
        print("\nQuery 2: Attacks per hour")
        
        self.run_pg_query(
            "Attacks per hour",
            """
            SELECT 
                date_trunc('hour', timestamp) as hour,
                COUNT(*) as attack_count
            FROM auth_logs
            WHERE event_type IN ('failed_password', 'auth_failure')
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 24
            """
        )
        
        self.run_es_query(
            "Attacks per hour",
            "auth-logs-*",
            {
                "query": {
                    "terms": {"event_type.keyword": ["failed_password", "auth_failure"]}
                },
                "aggs": {
                    "attacks_over_time": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "calendar_interval": "hour"
                        }
                    }
                },
                "size": 0
            }
        )
        
        # Query 3: Multi-dimensional aggregation
        print("\nQuery 3: Attacks by country and hour")
        
        self.run_pg_query(
            "Country + time aggregation",
            """
            SELECT 
                country_name,
                date_trunc('hour', timestamp) as hour,
                COUNT(*) as attack_count
            FROM auth_logs_with_geoip
            WHERE event_type IN ('failed_password', 'auth_failure')
            AND country_name IS NOT NULL
            AND timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY country_name, hour
            ORDER BY attack_count DESC
            LIMIT 50
            """
        )
        
        self.run_es_query(
            "Country + time aggregation",
            "auth-logs-*",
            {
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"event_type.keyword": ["failed_password", "auth_failure"]}},
                            {"exists": {"field": "geoip.country_name"}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": "now-7d"
                                    }
                                }
                            }
                        ]
                    }
                },
                "aggs": {
                    "by_country": {
                        "terms": {
                            "field": "geoip.country_name.keyword",
                            "size": 50
                        },
                        "aggs": {
                            "over_time": {
                                "date_histogram": {
                                    "field": "@timestamp",
                                    "calendar_interval": "hour"
                                }
                            }
                        }
                    }
                },
                "size": 0
            }
        )
        
        # Query 4: Full-text search
        print("\nQuery 4: Full-text search")
        
        self.run_pg_query(
            "Text search",
            """
            SELECT * FROM auth_logs
            WHERE log_message ILIKE %s
            LIMIT 100
            """,
            ('%invalid user%',)
        )
        
        self.run_es_query(
            "Text search",
            "auth-logs-*",
            {
                "query": {
                    "match": {
                        "log_message": "invalid user"
                    }
                },
                "size": 100
            }
        )
        
        # Query 5: Geographic filtering
        print("\nQuery 5: Attacks from Asia")
        
        self.run_pg_query(
            "Attacks from Asia",
            """
            SELECT country_name, COUNT(*) as attack_count
            FROM auth_logs_with_geoip
            WHERE continent_code = 'AS'
            AND event_type IN ('failed_password', 'auth_failure')
            GROUP BY country_name
            ORDER BY attack_count DESC
            """
        )
        
        self.run_es_query(
            "Attacks from Asia",
            "auth-logs-*",
            {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"geoip.continent_code": "AS"}},
                            {"terms": {"event_type.keyword": ["failed_password", "auth_failure"]}}
                        ]
                    }
                },
                "aggs": {
                    "by_country": {
                        "terms": {
                            "field": "geoip.country_name.keyword",
                            "size": 50
                        }
                    }
                },
                "size": 0
            }
        )
    
    def print_summary(self):
        """Print summary of results."""
        print("\n" + "="*80)
        print("BENCHMARK SUMMARY")
        print("="*80)
        
        # Group by query
        queries = {}
        for result in self.results:
            query = result['query']
            if query not in queries:
                queries[query] = {'PostgreSQL': None, 'Elasticsearch': None}
            queries[query][result['database']] = result
        
        print(f"\n{'Query':<40} {'PostgreSQL (ms)':<20} {'Elasticsearch (ms)':<20} {'Winner':<15}")
        print("-" * 95)
        
        pg_wins = 0
        es_wins = 0
        
        for query_name, dbs in queries.items():
            pg_time = dbs['PostgreSQL']['avg_ms'] if dbs['PostgreSQL'] else float('inf')
            es_time = dbs['Elasticsearch']['avg_ms'] if dbs['Elasticsearch'] else float('inf')
            
            if es_time == 0:  # Skip failed queries
                continue
                
            winner = 'PostgreSQL' if pg_time < es_time else 'Elasticsearch'
            if pg_time < es_time:
                pg_wins += 1
            else:
                es_wins += 1
            
            speedup = max(pg_time, es_time) / min(pg_time, es_time) if min(pg_time, es_time) > 0 else 0
            
            print(f"{query_name:<40} {pg_time:<20.2f} {es_time:<20.2f} {winner:<15} ({speedup:.2f}x)")
        
        print("\n" + "="*80)
        print(f"PostgreSQL wins: {pg_wins}")
        print(f"Elasticsearch wins: {es_wins}")
        print("="*80)
    
    def run_all(self):
        """Run all benchmarks."""
        print("Starting benchmark...")
        print(f"Timestamp: {datetime.now()}")
        
        # Check Elasticsearch connection
        try:
            info = self.es_client.info()
            print(f"Elasticsearch version: {info['version']['number']}")
        except Exception as e:
            print(f"WARNING: Could not connect to Elasticsearch: {e}")
        
        self.test_simple_queries()
        self.test_complex_queries()
        self.print_summary()
        
        self.pg_conn.close()

if __name__ == '__main__':
    benchmark = Benchmark()
    benchmark.run_all()
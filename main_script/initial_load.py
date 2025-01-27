import requests
import pandas as pd
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_batch
from sqlalchemy import create_engine
import logging
from dotenv import load_dotenv
import os
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ตั้งค่าการบันทึกข้อมูล
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}

def create_retry_session():
    """สร้าง Session ที่มีการตั้งค่า retry"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def clean_sector(sector):
    """ทำความสะอาดข้อมูล sector"""
    if not sector or sector.lower() in ['not found', 'unknown']:
        return 'Other'
    return sector.strip()

def parse_date(date_str):
    """แปลงสตริงวันที่เป็นวัตถุ datetime"""
    if not date_str:
        return None
        
    date_formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d"
    ]
    
    for date_format in date_formats:
        try:
            return datetime.strptime(date_str, date_format)
        except ValueError:
            continue
    
    return None

def extract_month(date):
    """Extract the month from a datetime object"""
    return date.month if date else None

def get_db_connection():
    """สร้างการเชื่อมต่อกับฐานข้อมูล"""
    return psycopg2.connect(**DB_CONFIG)

def get_table_name(year):
    """สร้างชื่อตารางตามปี"""
    return f'ransomware_data_{year}'

def clear_existing_data(year):
    """ล้างข้อมูลเก่าในตารางของปีที่ระบุ"""
    table_name = get_table_name(year)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"TRUNCATE TABLE {table_name} RESTART IDENTITY;")
                conn.commit()
                logger.info(f"ลบข้อมูลเก่าในตาราง {table_name} เรียบร้อยแล้ว")
    except Exception as e:
        logger.error(f"ข้อผิดพลาดในการลบข้อมูลในตาราง {table_name}: {e}")
        raise

def fetch_data(year):
    """ดึงข้อมูลสำหรับปีที่ระบุ"""
    url = f"https://api.ransomware.live/v1/victims/{year}"
    session = create_retry_session()
    
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"ข้อผิดพลาดในการดึงข้อมูลสำหรับปี {year}: {e}")
        return []
    finally:
        session.close()

def process_and_save_data_by_year(year):
    """ประมวลผลและบันทึกข้อมูลแยกตามปี"""
    engine = create_engine(
        f'postgresql://{DB_CONFIG["user"]}:{DB_CONFIG["password"]}@{DB_CONFIG["host"]}:{DB_CONFIG["port"]}/{DB_CONFIG["dbname"]}'
    )
    
    table_name = get_table_name(year)
    clear_existing_data(year)
    
    yearly_data = fetch_data(year)
    if not yearly_data:
        logger.error(f"ไม่พบข้อมูลสำหรับปี {year}")
        return
    
    processed_data = []
    for item in yearly_data:
        if isinstance(item, dict):
            discovered_date = parse_date(item.get('discovered', ''))
            attack_date = parse_date(item.get('published', ''))
            
            if discovered_date and discovered_date.year == year:
                processed_item = {
                    'sector': clean_sector(item.get('activity')),
                    'country': item.get('country', '').strip(),
                    'post_title': item.get('post_title', '').strip(),
                    'group_name': item.get('group_name', 'Other').strip() or 'Other',
                    'discovered_date': discovered_date,
                    'attack_date': attack_date,
                    'month': extract_month(discovered_date)
                }
                processed_data.append(processed_item)
    
    if not processed_data:
        logger.warning(f"ไม่พบข้อมูลที่ผ่านการประมวลผลสำหรับปี {year}")
        return
        
    df = pd.DataFrame(processed_data)
    
    # ทำความสะอาดข้อมูล
    df = df.dropna(subset=['discovered_date'])
    df['sector'] = df['sector'].replace(['', None, 'nan', float('nan'), 'Not Found'], 'Other')
    df['group_name'] = df['group_name'].replace(['', None, 'nan', float('nan')], 'Other')
    df['country'] = df['country'].replace(['nan', float('nan')], '')

    try:
        df.to_sql(table_name, engine, if_exists='append', index=False)
        logger.info(f"บันทึกข้อมูล {len(df)} รายการลงตาราง {table_name} เรียบร้อยแล้ว")
        
        # แสดงสถิติ
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    SELECT 
                        COUNT(*) as total_incidents,
                        COUNT(DISTINCT group_name) as group_count,
                        COUNT(DISTINCT NULLIF(country, '')) as country_count
                    FROM {table_name}
                """)
                stats = cur.fetchone()
                logger.info(f"\nสถิติสำหรับปี {year}:")
                logger.info(f"จำนวนเหตุการณ์: {stats[0]}")
                logger.info(f"จำนวนกลุ่ม: {stats[1]}")
                logger.info(f"จำนวนประเทศ: {stats[2]}")
                
    except Exception as e:
        logger.error(f"ข้อผิดพลาดในการบันทึกข้อมูลลงตาราง {table_name}: {e}")
        raise

if __name__ == "__main__":
    try:
        for year in range(2023, 2026):
            process_and_save_data_by_year(year)
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดในการทำงานของสคริปต์: {e}")
import requests
import pandas as pd
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import execute_batch
from sqlalchemy import create_engine
import logging
import os
from pathlib import Path
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json

# สร้างโครงสร้างไดเรกทอรี
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
NEW_RECORDS_DIR = DATA_DIR / 'new_records'
CURRENT_STATE_DIR = DATA_DIR / 'current_state'
LOG_DIR = DATA_DIR / 'logs'

# สร้างไดเรกทอรีถ้ายังไม่มี
for directory in [NEW_RECORDS_DIR, CURRENT_STATE_DIR, LOG_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ตั้งค่าการบันทึก log
current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
log_file = LOG_DIR / f'ransomware_update_{current_time}.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# โหลดตัวแปรสภาพแวดล้อม
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

def cleanup_old_files(directory, keep_last_n=5):
    """เก็บเฉพาะไฟล์ล่าสุด n ไฟล์ในไดเรกทอรี"""
    if 'logs' not in str(directory):
        files = sorted(directory.glob('*.*'), key=os.path.getctime, reverse=True)
        for old_file in files[keep_last_n:]:
            old_file.unlink()
            logger.info(f"ลบไฟล์เก่า: {old_file}")

def get_db_connection():
    """สร้างการเชื่อมต่อฐานข้อมูล"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล: {e}")
        raise

def get_latest_record_date():
    """ดึงวันที่ล่าสุดของข้อมูลจากฐานข้อมูล"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT MAX(discovered_date)
                    FROM ransomware_data_2025
                """)
                return cur.fetchone()[0]
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดในการดึงวันที่ล่าสุด: {e}")
        return None

def fetch_delta_data():
    """ดึงข้อมูลปี 2025 จาก API"""
    url = "https://api.ransomware.live/v1/victims/2025"
    session = create_retry_session()
    try:
        response = session.get(
            url,
            timeout=30,
            stream=True
        )
        response.raise_for_status()
        
        content = b''
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content += chunk
        
        return json.loads(content)
    except requests.RequestException as e:
        logger.error(f"เกิดข้อผิดพลาดในการดึงข้อมูลปี 2025: {e}")
        return []
    finally:
        session.close()

def parse_date(date_str):
    """แปลงสตริงวันที่เป็น datetime object"""
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

def extract_month(date_obj):
    """แยกเดือนออกจาก datetime object"""
    return date_obj.strftime("%m") if date_obj else None

def clean_sector(sector):
    """ทำความสะอาดข้อมูล sector"""
    if not sector or sector.strip() == '' or sector.strip().lower() == 'not found':
        return 'Other'
    return sector.strip()

def save_to_csv(df, data_type='new_records'):
    """บันทึก DataFrame เป็น CSV พร้อมเวลา"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'ransomware_2025_{timestamp}.csv'
    
    if data_type == 'new_records':
        save_path = NEW_RECORDS_DIR / filename
    else:  # current_state
        save_path = CURRENT_STATE_DIR / filename
    
    df.to_csv(save_path, index=False)
    logger.info(f"บันทึกข้อมูล {data_type} ไปยัง {save_path}")
    
    cleanup_old_files(NEW_RECORDS_DIR)
    cleanup_old_files(CURRENT_STATE_DIR)

def process_and_save_delta():
    """ประมวลผลและบันทึกเฉพาะข้อมูลใหม่ปี 2025"""
    
    engine = create_engine(
        f'postgresql://{DB_CONFIG["user"]}:{DB_CONFIG["password"]}@{DB_CONFIG["host"]}:{DB_CONFIG["port"]}/{DB_CONFIG["dbname"]}'
    )
    
    latest_date = get_latest_record_date()
    logger.info(f"วันที่ล่าสุดในฐานข้อมูล: {latest_date}")
    
    new_data = fetch_delta_data()
    
    processed_data = []
    for item in new_data:
        if isinstance(item, dict):
            discovered_date = parse_date(item.get('discovered', ''))
            attack_date = parse_date(item.get('published', ''))
            
            # ประมวลผลเฉพาะข้อมูลใหม่
            if (discovered_date and 
                discovered_date.year == 2025 and
                (latest_date is None or discovered_date > latest_date)):
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
        logger.info("ไม่มีข้อมูลใหม่ที่ต้องอัพเดต")
        return
    
    df = pd.DataFrame(processed_data)
    
    # ลบแถวที่มี discovered_date เป็นค่า Null
    df = df.dropna(subset=['discovered_date'])
    
    # แทนที่ค่าว่างและ NaN ด้วย 'Other'
    df['sector'] = df['sector'].replace(['', None, 'nan', float('nan'), 'Not Found'], 'Other')
    df['group_name'] = df['group_name'].replace(['', None, 'nan', float('nan')], 'Other')
    
    # ปล่อยให้ country เป็นค่าว่างหากไม่มีข้อมูล
    df['country'] = df['country'].replace(['nan', float('nan')], '')
    
    try:
        # บันทึกข้อมูลใหม่เป็น CSV ก่อนอัพเดตฐานข้อมูล
        save_to_csv(df, 'new_records')
        
        # บันทึกลง PostgreSQL
        df.to_sql('ransomware_data_2025', engine, if_exists='append', index=False)
        logger.info(f"บันทึกข้อมูลใหม่ {len(df)} รายการลงฐานข้อมูลสำเร็จ")
        
        # สร้างและบันทึกสถิติฐานข้อมูล
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_incidents,
                        COUNT(DISTINCT group_name) as unique_groups,
                        COUNT(DISTINCT NULLIF(country, '')) as unique_countries
                    FROM ransomware_data_2025
                """)
                stats = cur.fetchone()
                
                logger.info("\nสถิติปี 2025:")
                logger.info(f"จำนวนเหตุการณ์ทั้งหมด: {stats[0]}")
                logger.info(f"จำนวนกลุ่มที่ไม่ซ้ำกัน: {stats[1]}")
                logger.info(f"จำนวนประเทศที่ไม่ซ้ำกัน: {stats[2]}")
                
                # ส่งออกสถานะข้อมูลปัจจุบัน
                cur.execute("""
                    SELECT * FROM ransomware_data_2025
                    ORDER BY discovered_date DESC
                """)
                columns = [desc[0] for desc in cur.description]
                current_state_df = pd.DataFrame(cur.fetchall(), columns=columns)
                save_to_csv(current_state_df, 'current_state')
                
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดในการบันทึกลงฐานข้อมูล: {e}")
        raise

if __name__ == "__main__":
    try:
        process_and_save_delta()
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดในการทำงานของสคริปต์: {e}")
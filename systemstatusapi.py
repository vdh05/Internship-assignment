from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import uuid
import json
from typing import List
from fastapi.responses import StreamingResponse
import csv
import io
import system  
from fastapi import Query
app = FastAPI()


DATA_FILE = "system_status_db.json"


class SystemStatus(BaseModel):
    id: str
    timestamp: datetime
    os_name: str
    os_version: str
    is_up_to_date: bool
    disk_encryption: str
    antivirus_status: str
    basic_antivirus_status: str
    inactivity_sleep: dict  

def save_status_db(status_db: List[SystemStatus]):
    with open(DATA_FILE, "w") as f:
        json.dump([status.dict() for status in status_db], f, default=str)

def load_status_db() -> List[SystemStatus]:
    try:
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
            return [SystemStatus(**item) for item in data]
    except (FileNotFoundError, json.JSONDecodeError):
        return []

system_status_db = load_status_db()
if not system_status_db:
  
    save_status_db(system_status_db)

@app.put("/status/{status_id}", response_model=SystemStatus)
def update_status(status_id: str, status: SystemStatus):
    """Updates the status for a given machine ID."""
    for idx, existing_status in enumerate(system_status_db):
        if existing_status.id == status_id:
            system_status_db[idx] = status
            save_status_db(system_status_db)
            return status
    raise HTTPException(status_code=404, detail="Status not found")

@app.post("/status", response_model=SystemStatus)
def collect_status(status: SystemStatus):
    """Creates or updates system status for a machine."""
    # Check if the id exists
    for idx, existing_status in enumerate(system_status_db):
        if existing_status.id == status.id:
            
            updated = False
            for field in status.__fields__:
                new_value = getattr(status, field)
                old_value = getattr(existing_status, field)
                if new_value != old_value:
                    setattr(existing_status, field, new_value)
                    updated = True
            if updated:
                system_status_db[idx] = existing_status
                save_status_db(system_status_db)
            return existing_status

    system_status_db.append(status)
    save_status_db(system_status_db)
    return status

@app.get("/status", response_model=list[SystemStatus])
def list_status():
    """Lists all system statuses."""
    return system_status_db

@app.get("/status/filter", response_model=List[SystemStatus])
def filter_status(
    os_name: str = Query(default=None),
    os_version: str = Query(default=None),
    is_up_to_date: str = Query(default=None),  
    antivirus_status: str = Query(default=None),
    basic_antivirus_status: str = Query(default=None),
):
    """Filter system statuses based on any given parameters."""

    filtered = system_status_db

    if os_name:
        filtered = [s for s in filtered if s.os_name.lower() == os_name.lower()]
    if os_version:
        filtered = [s for s in filtered if s.os_version.lower() == os_version.lower()]
    if is_up_to_date is not None:
      
        is_up_to_date_bool = is_up_to_date.lower() == "true"
        filtered = [s for s in filtered if s.is_up_to_date == is_up_to_date_bool]
    if antivirus_status:
        filtered = [s for s in filtered if s.antivirus_status.lower() == antivirus_status.lower()]
    if basic_antivirus_status:
        filtered = [s for s in filtered if s.basic_antivirus_status.lower() == basic_antivirus_status.lower()]

    return filtered

@app.get("/status/{status_id}", response_model=SystemStatus)
def get_status(status_id: str):
    """Gets the status for a specific machine ID."""
    for status in system_status_db:
        if status.id == status_id:
            return status
    raise HTTPException(status_code=404, detail="Status not found")


@app.get("/status/export/csv")
def export_status_csv():
    """Exports all system statuses as a CSV file."""
    output = io.StringIO()
    writer = csv.writer(output)

  
    writer.writerow([
        "ID", "Timestamp", "OS Name", "OS Version", "Is Up To Date",
        "Disk Encryption", "Antivirus Status", "Basic Antivirus Status", "Inactivity Sleep"
    ])

    
    for status in system_status_db:
        writer.writerow([
            status.id,
            status.timestamp.isoformat(),
            status.os_name,
            status.os_version,
            status.is_up_to_date,
            status.disk_encryption,
            status.antivirus_status,
            status.basic_antivirus_status,
            json.dumps(status.inactivity_sleep) 
        ])

    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=system_status.csv"})

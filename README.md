# HarborLog

HarborLog is a simple, professional maritime vessel logging system with role-based access.

## Features

### Authentication and roles
- Login for **Admin**, **Crew**, **Engineer**, **Bridge Officer**, and **Read-only** users.
- Seeded default admin account:
  - Username: `admin`
  - Password: `admin123`

### Admin capabilities
- Create vessels.
- Create users (Admin/Crew/Engineer/Bridge Officer/Read-only).
- Assign Crew users to vessels.

### Crew capabilities
- Fast **New Entry** workflow for multiple entries throughout the day.
- Auto-filled timestamp per entry.
- Entry fields: vessel, category, notes.
- Categories: Weather, Operations, Safety, Issue/Delay.
- Chronological timeline view.
- Daily summary grouped by day.
- Export a selected day as PDF.
- Daily Vessel Report (one report per vessel per calendar day) with:
  - fuel burned
  - water onboard
  - POB count
  - meal count
  - JSA count
  - preventers checked
  - master remarks
- Create/edit Daily Vessel Report and export it to PDF.
- Midnight Daily Ops Report (master daily report, one per vessel per calendar day; midnight intended but editable anytime) with:
  - auto report timestamp
  - report_date, auto report_timestamp, vessel
  - position_type + position_text
  - status + status notes
  - destination/location and optional ETA
  - weather: wind, seas, visibility
  - fuel onboard, fuel used 24h, water onboard, lube oil onboard
  - fuel ticket number + optional PDF attachment (.pdf only), POB, optional next crew change date
  - optional JSA count + optional JSA breakdown
- Read-only OM View and Office View formats (email-style summaries).
- PDF export for OM View and Office View.
- Fuel ticket attachment is PDF-only and can be opened/downloaded via link in OM/Office views.
- Admin view of all Daily Ops reports.
- Access control: only assigned crew (and admin) can access vessel Daily Ops reports.


### Fuel module (event-based)
- Tank model per vessel (`Main`/`Day`, port/starboard) with default seeded tanks.
- Event types:
  - `transfer_internal`
  - `bunker_received`
  - `offload_external`
  - `receive_external`
  - `sounding`
  - `charter_on`
  - `charter_off`
  - `correction`
- Operational mode captured on each event: `Dockside`, `Underway`, `On DP`.
- No deletion endpoints for fuel events (immutable event history).
- Gallons are write-once (no edit endpoint).
- Correction events require original event reference + reason; charter on/off events are locked from correction.
- Dynamic tank balances are calculated from event history (not stored as mutable balances).
- RBAC enforcement:
  - **Engineer** and **Bridge Officer** can create fuel events.
  - Other roles are read-only for fuel events.
- Daily Vessel Report API includes auto-calculated 24-hour transfer totals from fuel events.

### Data model guarantees
- Stable UUID IDs for records.
- ISO-8601 UTC timestamps for created/updated metadata.

## Tech stack
- Frontend: Vanilla HTML/CSS/JavaScript
- Backend API: Python standard library HTTP server
- Database: SQLite (`sqlite3`)
- PDF Export: Lightweight custom PDF generator

## Run locally

```bash
python app.py
```

Open: `http://localhost:3000`

Database file is created automatically at `data/harborlog.db`.


## Single Vessel Mode
- `SINGLE_VESSEL_MODE=true` (default)
- `HOME_VESSEL_NAME="Blue Sea"` (default)
- On startup, HarborLog ensures the home vessel exists.
- New Crew users are auto-assigned to the home vessel.
- Manual assignment UI/workflows are disabled in this mode.

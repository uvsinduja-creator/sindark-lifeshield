# LifeShield Architecture Notes

_Fill this in as a team during Week 1 — writing it in your own words is
what forces everyone to actually understand the design, not just copy it._

## Component Diagram
(paste/describe your diagram here)

## Data Flow
Collector -> Agent -> Event Bus -> Normalizer -> Feature Engine ->
ML Models -> Correlation Engine -> Risk Engine -> Decision Engine ->
Response Layer -> Dashboard / Local LLM Explanation

## Event Schema Decisions
- Why we chose the fields we chose in storage/schema.py
- Any fields we debated adding/removing and why

## Open Questions
- 
- 

## Team Responsibility Split
| Person | Owns | Weeks |
|---|---|---|
| | | |

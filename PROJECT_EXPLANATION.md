# 🛡️ Simple Guide: Multi-Agent Cyber Threat Intelligence System

Welcome to the **Multi-Agent Cyber Threat Intelligence (CTI) System**! 

If the technical term sounds complicated, don't worry. This document explains exactly what the system does in plain English using a simple analogy.

---

## 🏥 The "Digital Hospital" Analogy
Imagine your computer network is a busy hospital. Thousands of people (data packets) enter and leave every second. Most are just normal visitors, but some might be dangerous intruders (hackers, viruses). 

To keep the hospital safe, we hired a team of strict, incredibly fast robotic staff members—these are our **AI Agents**. Each agent has exactly **one specific job**, and they pass information to each other on an assembly line.

Here is the team:

### 1. 📋 The Receptionist (Data Collection Agent)
**What it does:** It stands at the front door and writes down the details of every single person who walks in or out. Where did they come from? Which door did they use? How large is their luggage? 
*Technical term: Reads real-time network traffic logs.*

### 2. 🩺 The Triage Nurse (Preprocessing Agent)
**What it does:** It takes the messy notes from the Receptionist, cleans them up, translates them into numbers, and organizes them perfectly so the doctors can read them quickly.
*Technical term: Cleans and normalizes raw data for Machine Learning.*

### 3. 🤔 The Diagnostician (Anomaly Detection Agent)
**What it does:** This AI doctor looks straight at the organized data and asks: *"Does this look weird?"* If someone walked in wearing a ski mask carrying a ticking box, the doctor flags them as "abnormal."
*Technical term: Uses an Isolation Forest algorithm to find statistical anomalies.*

### 4. 🔬 The Specialist (Threat Classification Agent)
**What it does:** Once the Diagnostician flags someone as "weird," the Specialist gets called in to identify the exact disease. Are they a burglar? A spy? A vandal?
*Technical term: Uses a Random Forest algorithm to classify the threat (e.g., Malware, DDoS, Phishing).*

### 5. 🗣️ The Translator (Explainability Agent)
**What it does:** AI can sometimes be a "black box" that just spits out a warning. The Translator looks at the AI's decision and writes a simple English sentence explaining **why** the alarm was pulled. (e.g., *"I flagged this because the luggage was unsually large and they tried to enter through the restricted basement door."*)
*Technical term: Generates human-readable reasoning and feature importance.*

### 6. ⚠️ The Chief of Security (Risk Assessment Agent)
**What it does:** Looks at the situation and assigns a panic level. Is it a "Low" risk annoyance, or a "Critical" threat requiring immediate action? It gives the threat a score from 1 to 100.
*Technical term: Calculates overall risk severity.*

### 7. 👮 The Enforcer (Response Agent)
**What it does:** Takes action based on the Chief's orders. It writes the exact instructions on how to stop the intruder. (e.g., *"Lock the basement door immediately and call the cops."*)
*Technical term: Generates automated response recommendations and firewall rules.*

---

## 🔗 How do they talk to each other?
If they all sit in different rooms, how do they coordinate?
We use a tool called **LangGraph**, which acts like an automated intercom system (The **Orchestrator**). It takes the data from Agent 1, passes it to Agent 2, then to Agent 3, and so on.

## 📺 How do you watch them work?
You sit in the security room looking at the **Dashboard** (built with **Streamlit**). It shows you a live feed of the hospital doors. Every time the team catches an intruder, a red alarm pops up on your screen detailing exactly who the attacker is, why they were caught, and what to do about it.

---

### That's it!
By splitting the work among multiple specialized AI agents, the system is extremely fast, highly accurate, and very easy to upgrade or understand.

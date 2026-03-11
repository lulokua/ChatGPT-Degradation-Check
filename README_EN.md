```
  ██████╗██╗  ██╗ █████╗ ████████╗ ██████╗ ██████╗ ████████╗    ██████╗ ███████╗ ██████╗ ██████╗  █████╗ ██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗    
 ██╔════╝██║  ██║██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗╚══██╔══╝    ██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║    
 ██║     ███████║███████║   ██║   ██║     ██║   ██║   ██║       ██║  ██║█████╗  ██║   ██║██████╔╝███████║██║  ██║███████║   ██║   ██║██║   ██║██╔██╗ ██║    
 ██║     ██╔══██║██╔══██║   ██║   ██║     ██║   ██║   ██║       ██║  ██║██╔══╝  ██║   ██║██╔══██╗██╔══██║██║  ██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║    
 ╚██████╗██║  ██║██║  ██║   ██║   ╚██████╗╚██████╔╝   ██║       ██████╔╝███████╗╚██████╔╝██║  ██║██║  ██║██████╔╝██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║    
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═════╝    ╚═╝       ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    
                                                                                                                                                             
    ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗    ████████╗ ██████╗  ██████╗ ██╗         ████████╗██╗  ██╗██╗███████╗    ██╗             ██╗
    ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║         ╚══██╔══╝██║  ██║██║██╔════╝    ╚██╗           ██╔╝
    ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║          ██║   ██║   ██║██║   ██║██║            ██║   ███████║██║███████╗     ╚██╗         ██╔╝ 
    ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║          ██║   ██║   ██║██║   ██║██║            ██║   ██╔══██║██║╚════██║      ╚██╗       ██╔╝  
    ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗       ██║   ██║  ██║██║███████║       ╚██╗     ██╔╝   
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝        ╚██╗   ██╔╝    
                                                                                                                                              ╚█████╔╝     
                                                                                                                                                ╚════╝      
```

# ChatGPT Degradation Detection Pro

> A userscript that fuses IP reputation and PoW (Proof of Work) difficulty signals to assess whether your current ChatGPT session is at risk of "intelligence degradation" (降智).

---

## Overview

Many people judge whether ChatGPT is "degraded" by looking at a single IP risk score or a single PoW difficulty value. Both approaches are unstable.

This project takes a different approach:

- Uses `IPPure` to provide a baseline risk score for your current IP
- Uses `PoW difficulty` from ChatGPT's `chat-requirements` endpoint as real-time evidence
- Performs trend, volatility, and persistence analysis using local historical data
- Outputs a comprehensive risk assessment closer to real-world usage experience

In other words, instead of simply reading a single score, this script performs a "degradation risk analysis" tailored to actual usage scenarios.

## Special Note

> Current real-world feedback shows this project is particularly effective in the **ChatGPT Business** scenario. It doesn't just "work" — it provides strong practical value for assessing node quality, identifying degradation risks, and helping users filter available connection routes.
>
> However, for **ChatGPT Plus** and **ChatGPT Pro** users, the sample size and feedback are still insufficient for definitive conclusions. In summary: the tool has proven high value in **Business** scenarios, while **Plus / Pro** scenarios require more real-world samples for continued observation.

## Key Features

| Capability | Description |
| --- | --- |
| **Real Exit IP Detection** | Obtains your true exit IP via `chatgpt.com/cdn-cgi/trace` |
| **IP Reputation Analysis** | Queries `IPPure` risk control data for baseline IP risk scoring |
| **PoW Difficulty Collection** | Monitors `chat-requirements` / `sentinel` responses to extract `proofofwork.difficulty` |
| **Historical Trend Algorithm** | Session aggregation, time decay, EMA trends, and volatility pattern recognition on local history |
| **Fused Assessment** | Combines `IPPure + historical behavior + PoW` into unified `compositeRisk` |
| **Risk Visualization** | Provides mini cards, full-screen detail view, risk indicators, and trend hints |
| **Local Storage** | All historical samples stored locally in the browser — no external database required |
| **Usage Statistics** | Built-in model usage statistics to track daily model switching |

## How It Determines "Degradation Risk"

This script doesn't rely on a single signal. It examines three types of evidence:

### 1. Current IP Quality

- Current `IPPure` risk score
- Whether this IP has been consistently stable
- Recent frequency of node switching

### 2. Historical Behavior Trajectory

- Whether recent detections show improvement or deterioration
- Whether scores fluctuate like shared/rotating nodes
- Whether continuous deterioration or sustained high risk has occurred

### 3. ChatGPT PoW Difficulty

- Current `PoW difficulty` level
- Whether PoW has been consistently high or low recently
- Whether PoW signals align with IP risk conclusions

Final output includes:

- `compositeRisk`: Comprehensive risk score
- `stability`: Stability metric
- `confidence`: Confidence level
- `volatility`: Volatility index
- `trend`: Trend direction
- `verdict`: Final conclusion

## Why This Approach Is More Reliable Than Single-Score Methods

### Problems with IP-Only Assessment

- Single scores are affected by short-term fluctuations
- Cannot distinguish "currently good" from "recently deteriorating"
- Cannot identify锯齿波动 (sawtooth volatility) of shared/rotating nodes

### Problems with PoW-Only Assessment

- PoW is affected by question complexity, page state, and request path
- A single low PoW doesn't necessarily mean degradation
- PoW is better suited as supplementary evidence, not sole determinant

### Advantages of This Solution

- IP risk provides the baseline
- Historical algorithms analyze trends and stability
- PoW provides supplementary evidence for current entry quality
- Increases confidence when multiple signals align, decreases when they conflict

## Installation

### Requirements

- **Browser**: Chrome / Edge / Firefox
- **Userscript Manager**: [Tampermonkey](https://www.tampermonkey.net/) or [Violentmonkey](https://violentmonkey.github.io/)

### Steps

1. Install a userscript manager (Tampermonkey or Violentmonkey)
2. Import [ChatGPT降智检测.user.js](./ChatGPT降智检测.user.js) into your script manager
3. Open `https://chatgpt.com/`
4. On first page load, the script will automatically inject the detection panel

## Usage

1. Open the ChatGPT web interface
2. Wait for the script to complete the current exit IP detection
3. Send a few real messages to allow the script to accumulate samples
4. Click the sidebar button to view the mini card
5. Click "View Detailed Analysis" to enter the full analysis page

**Recommendations:**

- Don't rely solely on the first result
- Accumulate several real sessions before drawing conclusions
- If you frequently switch nodes, stabilize on one node before observing

## Interpreting Results

### Risk Levels

| Composite Score | Meaning | Recommendation |
| --- | --- | --- |
| `0-25` | Low risk, usually stable | Safe to continue using |
| `26-40` | Gray zone — consider trend and stability | Continue monitoring |
| `41-55` | Elevated risk, becoming unstable | Consider switching nodes |
| `56+` | High risk, clearly unsuitable | Switch immediately |

### Key Metrics

| Metric | Meaning |
| --- | --- |
| `compositeRisk` | Comprehensive risk — the core final score |
| `stability` | Historical stability — higher is better |
| `confidence` | Reliability of current conclusion — higher is more trustworthy |
| `volatility` | Volatility magnitude — higher is less stable |
| `trend` | Recent trend: deteriorating, improving, or flat |
| `powRisk` | PoW dimension risk — higher indicates weaker entry quality |

## Who Is This For?

- ChatGPT users who frequently switch proxies/nodes
- Users wanting to judge whether an IP is prone to "degradation"
- Users wanting to combine PoW and IP reputation into a unified view
- Users wanting long-term, accumulative node quality observation

## Privacy & Data Notice

This project stores data only in your local browser by default — no remote user database is established.

**Locally Stored Data:**

- IP risk control historical scores
- Timestamps
- Exit IPs
- PoW difficulty history
- Model usage statistics

**Privacy Notes:**

- All data stored in browser `localStorage`
- The script does NOT upload your chat content to any project server
- To identify models and PoW, the script locally parses some requests/responses on the page, but results are used only for local computation

## File Structure

| File | Description |
| --- | --- |
| [ChatGPT降智检测.user.js](./ChatGPT降智检测.user.js) | Main userscript |
| [算法说明.md](./算法说明.md) | Full algorithm documentation (Chinese) |
| [README.md](./README.md) | Chinese documentation |
| [README_EN.md](./README_EN.md) | This English documentation |

## Current Version

- **Script Version**: `3.4.0`
- **Algorithm Version**: `v5`

## Limitations

Please understand this as a **risk assessment tool**, not an "absolute truth machine."

While it significantly improves judgment quality, it still has boundaries:

- Single PoW readings cannot directly represent real-world experience
- Conclusions will be conservative with insufficient samples
- If `IPPure` falls back to non-specific IP queries, current scores may deviate from the true exit IP
- If ChatGPT's web structure or API fields change in the future, the script may require updates

---

<p align="center">Made with ❤️ for the ChatGPT community</p>

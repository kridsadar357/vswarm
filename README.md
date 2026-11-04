# swarmdeck

จอ terminal แบบสดสำหรับดู Claude Code ทำงาน ว่าโมเดลหลักกำลังทำอะไร ส่งงานให้ subagent ตัวไหน แต่ละตัวคืบหน้าแค่ไหน
พร้อมแสดงการตัดสินใจของ Jev และคำแนะนำจาก advisor

![demo](docs/demo.png)

```bash
bun install
bun src/cli.ts demo                      # ดูตัวอย่าง ไม่เรียก API
bun src/cli.ts run "หาว่าโปรเจคนี้ใช้ auth ที่ไหนบ้าง" --model sonnet -- --allowedTools "Agent Read Grep Glob"
```

ขนาด terminal ที่ต้องใช้คือ 92×47 กด `q` เพื่อออก

## ดู session จริง

มี 2 วิธี

1. **`swarmdeck run "<prompt>"`** รัน `claude -p` พร้อมติด hook ชั่วคราวให้เอง แล้วแสดงจอสดจนจบ จากนั้นพิมพ์คำตอบ
   ใส่ flag ของ claude ต่อท้าย `--` ได้ เช่น `--allowedTools`
2. **ติด hook ถาวรในโปรเจค** แล้วเปิดจอไว้อีกหน้าต่าง

   ```bash
   bun src/cli.ts install ~/develop/WMS     # เขียนลง ~/develop/WMS/.claude/settings.local.json
   bun src/cli.ts watch                     # เปิดอีก terminal หนึ่ง
   bun src/cli.ts uninstall ~/develop/WMS   # ถอดออก (hook อื่นที่มีอยู่จะไม่ถูกแตะ)
   ```

   ถ้าใช้ `--global` จะติดกับทุก session

## แต่ละช่องเอาข้อมูลจากไหน

| ช่องบนจอ | แหล่งข้อมูล |
|---|---|
| โมเดลหลัก, effort, จำนวน tool | hook `PreToolUse` และโมเดลที่อ่านจากท้าย transcript |
| subagent ทั้ง 3 ช่อง | `PreToolUse(Agent)` จับคู่กับ `SubagentStart`/`SubagentStop` ใช้ `agent_id` แยก tool call ของแต่ละตัว |
| แถบความคืบหน้า subagent | ใน session จริงคือจำนวน tool ที่เรียกไปแล้ว เพราะ Claude Code ไม่ได้บอกเป็นเปอร์เซ็นต์ ถ้าส่ง `agent.progress` มาเองจึงจะแสดงเป็น % |
| JEV fork layer | คำสั่ง `swarmdeck jev …` (ต้องตั้ง `JEV_API_KEY`) หรือ event `decision` ค่า p ตั้งแต่ 0.8 ขึ้นไปนับเป็น sharp |
| advisor (ช่องซ้าย) | event `advisor` ถ้าไม่มี advisor ช่องนี้จะแสดงสถิติของ session แทน |
| session log | ทุก event ข้างบนรวมกัน |

ในเวอร์ชัน 2.1.318 Claude Code ยังไม่มีโหมด advisor ในตัว ช่องนี้จึงรอรับ event จากตัวที่เราต่อเอง เช่น:

```bash
bun src/cli.ts emit '{"type":"advisor","model":"claude-opus-5-5","status":"on call","mark":"before a plan","note":"plan skips auth","tokens":412000}'
bun src/cli.ts jev --q "which file" --state "กำลังแก้ rate limit ของ /api/login" test/api.spec.ts src/api/login.ts
```

## Event

ไฟล์ event เป็น JSONL อยู่ที่ `~/.swarmdeck/events.jsonl` เปลี่ยนที่ได้ด้วย `SWARMDECK_FILE` หรือ `--file`
ชนิดของ event ทั้งหมดอยู่ใน `src/state.ts` (`DeckEvent`)

## โครงสร้าง

```
src/cli.ts     คำสั่งทั้งหมดและตัววาดจอ
src/view.ts    layout ของจอ
src/state.ts   ชนิด event และการรวมเป็นสถานะ
src/hook.ts    แปลง payload ของ Claude Code hook เป็น event
src/follow.ts  อ่านไฟล์ event ต่อเนื่อง
src/jev.ts     เรียก Jev (typesafe.ai systemone)
src/demo.ts    สคริปต์ตัวอย่าง
src/screen.ts  ตาราง character → ANSI / HTML (รองรับสระและวรรณยุกต์ไทย)
```

ทดสอบ: `bun test` · ตรวจชนิด: `bunx tsc --noEmit`

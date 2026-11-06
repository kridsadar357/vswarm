# vswarm (ภาษาไทย)

**ตรวจเครื่องตัวเองก่อนแตะ production**

การโจมตียุคนี้มักเข้าทางคนที่ถือกุญแจ เช่น Homebrew package ที่ถูกดัดแปลง, "แบบทดสอบเขียนโค้ด" จากผู้สัมภาษณ์งานปลอม,
npm package ชื่อเลียนแบบ โค้ดอันตรายรันในนามของคุณ แล้วใช้ credential ที่เครื่องจำไว้ ฝั่ง server เห็นแค่ token ที่ถูกต้อง

vswarm อยู่ตรงก่อนขั้นสุดท้ายนั้น มันจำว่าเครื่องตอนสะอาดหน้าตาเป็นยังไง บอกว่าอะไรเปลี่ยนไป
หา credential อายุยาวที่น่าขโมย และไม่ยอมปล่อยสิทธิ์เข้า production (ssh, AWS, Kubernetes) จากเครื่องที่ตรวจไม่ผ่าน

## ติดตั้ง

ใช้ได้ทั้ง macOS และ Linux ต้องมี [Bun](https://bun.sh) และ git บน Linux ถ้าจะใช้ `vswarm try` ต้องลง bubblewrap และ strace ด้วย (`sudo apt install bubblewrap strace`)

บน Linux vswarm ตรวจ systemd unit, XDG autostart, `/etc/ld.so.preload` และ process จาก `/proc`
- `vswarm try` ใช้ bubblewrap: ซ่อน home ทุกคน ซ่อน `/run` (socket ของ Docker, D-Bus, keyring) ระบบเป็นอ่านอย่างเดียว และมี network กับ pid ของตัวเอง
- strace บันทึกทุกไฟล์ที่โค้ดพยายามเปิด และทุกที่อยู่ที่พยายามต่อออกไป
- Ubuntu 24.04 จำกัด user namespace: `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`

```bash
curl -fsSL https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.sh | sh
```

## ใช้งาน

```bash
vswarm scan                          # ตรวจตอนนี้
vswarm baseline                      # บนเครื่องที่ไว้ใจ: บันทึกว่านี่คือสภาพสะอาด
vswarm diff                          # ทีหลัง: อะไรเปลี่ยนไปจาก baseline
vswarm secrets                       # credential อายุยาวในเครื่อง (ไม่แสดงค่า)
vswarm gate ssh "prod-*"             # ssh เข้า prod-* ได้เฉพาะตอนเครื่องผ่าน
vswarm respond                       # เจอของผิดปกติ: ล็อก เก็บหลักฐาน เปลี่ยน credential กักกัน รายงาน
vswarm selftest                      # ฝังภัยจำลองใน home ปลอม แล้ววัดว่าจับได้กี่ข้อ
vswarm try ./assignment -- npm install   # รันโค้ดที่ไม่ไว้ใจใน sandbox แล้วรายงานว่ามันพยายามทำอะไร
vswarm ca init && vswarm gate ssh --cert "prod-*"   # ใบรับรอง ssh อายุ 15 นาที ออกให้เมื่อเครื่องผ่านเท่านั้น
vswarm canary plant aws                  # วาง credential ล่อ ถ้ามีคนใช้จะได้ e-mail เตือน
vswarm guard on                          # npm, pip, brew … ถาม vswarm ก่อนติดตั้งทุกครั้ง
```

### vswarm agents: ตรวจ AI agent และ MCP

AI agent รันโค้ดด้วยสิทธิ์ของคุณ และการตั้งค่าเป็นตัวกำหนดว่ามันเริ่มอะไรเองได้บ้าง vswarm ตรวจ:
- MCP server ของ Claude Code (ทุก profile), Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI และ Codex
- hook และ `statusLine` ของ Claude Code, โหมด permission และ plugin

ระดับความรุนแรง:
- **สูง (หยุด):** MCP หรือ hook ที่ดาวน์โหลดแล้วรัน หรือรันจากโฟลเดอร์ชั่วคราว, MCP ที่ใช้ชื่อ package เลียนแบบ
- **กลาง (เตือน):** MCP server หรือ hook ที่เพิ่มหรือเปลี่ยนตั้งแต่ baseline, agent ได้สิทธิ์กว้างขึ้น, MCP ที่ต่อแบบ http ไม่เข้ารหัส, token ที่วางไว้ตรงๆ ใน config

ดูรายการทั้งหมดด้วย `vswarm agents`

### vswarm guard: ตรวจ package ก่อนติดตั้ง

`vswarm guard on` ครอบคำสั่ง npm, npx, pnpm, yarn, bun, bunx, pip, pip3, uv, uvx, pipx และ brew ใน shell
ตอนสั่งติดตั้ง vswarm จะตรวจก่อนที่สคริปต์ติดตั้งจะได้รัน ส่วนคำสั่งอื่น เช่น `npm run dev` ไม่ผ่าน vswarm เลย

- **หยุดและถามก่อน:** package ที่มีรายงานว่าอันตราย (OSV `MAL-`), ชื่อเลียนแบบ package ดัง (axois, reqeusts), ชื่อที่ไม่มีจริงแต่คล้ายของดัง, package ที่เพิ่งสร้างไม่ถึง 30 วัน มีคนโหลดน้อย และมีสคริปต์ติดตั้ง
- **เตือนแล้วไปต่อ:** เวอร์ชันที่เพิ่งออกไม่ถึง 48 ชั่วโมง (ช่วงที่ release ถูกแฮ็กมักโดนดึงออก), ติดตั้งจาก git URL หรือ tarball, Homebrew tap ของบุคคลที่สาม
- `npm install` เปล่าๆ จะเช็คทุกเวอร์ชันใน lockfile กับ OSV
- ข้าม vswarm ครั้งเดียวด้วย `command npm …` ปิดด้วย `vswarm guard off` ตรวจเองด้วย `vswarm pkg npm install <ชื่อ>`

### vswarm try: รันโค้ดที่ไม่ไว้ใจ

ใช้กับ "แบบทดสอบ" จากการสัมภาษณ์งาน, repo ที่คนแปลกหน้าส่งมา หรือ installer

- **ก่อนรัน:** อ่านโค้ดหาสิ่งที่ตั้งให้รันเอง เช่น install script, VS Code task ที่รันทันทีเมื่อเปิดโฟลเดอร์, ตัวโหลดที่ซ่อนใน config file, `eval(atob(…))`
- **ระหว่างรัน:** รันบนสำเนาใน sandbox ของ macOS
  - อ่าน home, keychain และ clipboard ไม่ได้
  - ใช้ HOME ปลอม ไม่ได้รับ token ของคุณ
  - ออกเน็ตไม่ได้ ทุก host ที่พยายามติดต่อถูกบันทึกไว้
- **รายงาน:** บอกว่ามันพยายามทำอะไร เช่น อ่าน `~/.ssh`, รหัสผ่านใน browser หรือ wallet, ฝัง login job, ต่อออกไปหา IP ภายนอก

```

ผล preflight: **PASS** ไปต่อ · **WARN** ไปต่อได้แต่ควรแก้ · **BLOCK** ไม่ปล่อย credential

## ความเป็นส่วนตัว

- ข้อมูลอยู่ในเครื่องที่ `~/.vswarm/sec` เจ้าของเครื่องอ่านได้คนเดียว ไม่มี telemetry
- ส่งออกอย่างเดียว คือชื่อและเวอร์ชันของ package ไปที่ `api.osv.dev` เพื่อเช็คกับรายการ package อันตราย (ใช้ `--offline` เพื่อปิด)
- ถ้าเปิด `vswarm guard` ชื่อ package ที่กำลังจะติดตั้งจะถูกส่งไปถาม registry ต้นทางด้วย (เป็นชื่อเดียวกับที่ package manager กำลังจะส่งอยู่แล้ว)
- การตรวจ credential บอกแค่ตำแหน่งกับชนิด ไม่อ่านค่าออกมา

## ข้อจำกัด

- จับ malware ที่ซ่อนตัวเก่ง หรือโค้ดที่รันครั้งเดียวแล้วไม่เหลือร่องรอยไม่ได้
- ถ้า credential ถูกขโมยไปแล้วและถูกใช้จากเครื่องผู้โจมตี vswarm มองไม่เห็น ต้องป้องกันฝั่ง server ด้วย credential อายุสั้น กุญแจฮาร์ดแวร์ และการตรวจสภาพเครื่อง
- บน macOS การตรวจ extension ของ browser ต้องให้สิทธิ์ Full Disk Access กับ terminal ถ้าไม่ให้ vswarm จะบอกว่าตรวจไม่ได้ ไม่ทำเหมือนว่าผ่าน

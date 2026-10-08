// Skill 包校验单测（lib/pkg.js）：validateSkillPackage / parseYamlFrontMatter / isPathTraversal
// 经 makePkg({ objStore: fake }) 注入假对象存储，buildZip 造真实 zip 包，全程无磁盘依赖。
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const makePkg = require("../../lib/pkg");

const fakeObjStore = (bufferByKey) => ({
  get: async (key) => {
    const buf = bufferByKey[key];
    return buf ? { buffer: buf } : null;
  },
});

const pkgOf = (bufferByKey) => makePkg({ objStore: fakeObjStore(bufferByKey) });

const SKILL_MD_OK = "---\nname: demo-skill\ndescription: 一个演示技能\n---\n\n# 正文";

// 用 pkg 自身的 buildZip 造包（避免手写 zip 二进制）
function zipBuffer(entries) {
  const p = makePkg({ objStore: fakeObjStore({}) });
  return p.buildZip(entries.map(([name, data]) => ({ name, data: Buffer.from(data, "utf8") })));
}

test("parseYamlFrontMatter：标准 front matter 解析出 name/description", () => {
  const p = makePkg({ objStore: fakeObjStore({}) });
  const fm = p.parseYamlFrontMatter(SKILL_MD_OK);
  assert.equal(fm.name, "demo-skill");
  assert.equal(fm.description, "一个演示技能");
});

test("parseYamlFrontMatter：无 front matter / 无结束符返回 null", () => {
  const p = makePkg({ objStore: fakeObjStore({}) });
  assert.equal(p.parseYamlFrontMatter("没有 front matter"), null);
  assert.equal(p.parseYamlFrontMatter("---\nname: x\n（无结束符）"), null);
});

test("parseYamlFrontMatter：值两侧引号被剥离", () => {
  const p = makePkg({ objStore: fakeObjStore({}) });
  const fm = p.parseYamlFrontMatter('---\nname: "quoted"\ndescription: \'single\'\n---');
  assert.equal(fm.name, "quoted");
  assert.equal(fm.description, "single");
});

test("isPathTraversal：../ 与 ..\\ 拦截，正常路径放行", () => {
  const p = makePkg({ objStore: fakeObjStore({}) });
  assert.equal(p.isPathTraversal("a/../../etc/passwd"), true);
  assert.equal(p.isPathTraversal("..\\..\\win"), true);
  assert.equal(p.isPathTraversal("SKILL.md"), false);
  assert.equal(p.isPathTraversal("sub/dir/README.md"), false);
});

test("validateSkillPackage：合法 zip（含合规 SKILL.md）→ valid + name/description", async () => {
  const buf = zipBuffer([["SKILL.md", SKILL_MD_OK], ["tools/echo.js", "console.log(1)"]]);
  const p = pkgOf({ "demo.zip": buf });
  const r = await p.validateSkillPackage("demo.zip");
  assert.equal(r.valid, true);
  assert.equal(r.name, "demo-skill");
  assert.equal(r.description, "一个演示技能");
});

test("validateSkillPackage：缺 SKILL.md → 拒绝并说明", async () => {
  const buf = zipBuffer([["README.md", "hello"]]);
  const p = pkgOf({ "bad.zip": buf });
  const r = await p.validateSkillPackage("bad.zip");
  assert.equal(r.valid, false);
  assert.match(r.error, /缺少 SKILL\.md/);
});

test("validateSkillPackage：SKILL.md 缺 front matter 字段 → 拒绝", async () => {
  const buf = zipBuffer([["SKILL.md", "# 只有正文，没有 front matter"]]);
  const p = pkgOf({ "nofm.zip": buf });
  const r = await p.validateSkillPackage("nofm.zip");
  assert.equal(r.valid, false);
  assert.match(r.error, /front matter/);
});

test("validateSkillPackage：SKILL.md 缺 name → 拒绝", async () => {
  const buf = zipBuffer([["SKILL.md", "---\ndescription: 只有描述\n---\n正文"]]);
  const p = pkgOf({ "noname.zip": buf });
  const r = await p.validateSkillPackage("noname.zip");
  assert.equal(r.valid, false);
  assert.match(r.error, /缺少 name/);
});

test("validateSkillPackage：不支持的格式 → 拒绝", async () => {
  const p = pkgOf({ "x.exe": Buffer.from("MZ") });
  const r = await p.validateSkillPackage("x.exe");
  assert.equal(r.valid, false);
  assert.match(r.error, /不支持的 skill 包格式/);
});

test("validateSkillPackage：制品不存在/为空 → 拒绝", async () => {
  const p = pkgOf({});
  const r = await p.validateSkillPackage("ghost.zip");
  assert.equal(r.valid, false);
  assert.match(r.error, /制品为空/);
});

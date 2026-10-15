// better-sqlite3 行类型放宽（项目级决策）：未显式声明泛型的 Statement.get()/all()
// 回退为 any（与 v8 运行时行为一致），由各调用点的 JSDoc 按需收窄。
// 全库 .get().xxx / .all() 调用点众多，逐点收窄属 B 档后续增量。
import type { Database, Statement } from "better-sqlite3";

declare module "better-sqlite3" {
  interface Statement<BindObj = unknown, Result = unknown> {
    get(...params: BindObj[]): any;
    all(...params: BindObj[]): any[];
    iterate(...params: BindObj[]): any;
  }
}

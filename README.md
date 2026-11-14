# fat-carving-validator
Python FAT 删除文件恢复校验库，处理目录项、簇链、文件尾标记和候选去重

> **重要：本工具输出的所有结果都只是"候选"（candidate），不代表恢复成功。**
> 即使 JPEG/PDF 的起止签名完全匹配，也只是辅助证据。簇链可能被截断、
> 交叉链接、部分覆写，签名也可能恰好残留或被伪造。任何结论都需要人工
> 结合簇链完整性与内容校验进一步确认。

## 功能

- **只读访问**：镜像以 `O_RDONLY` 打开，全程 `pread`，绝不写回证据盘
- **FAT12/16/32**：解析 boot sector / BPB，按微软规范以簇总数判定 FAT 类型
- **目录解析**：短文件名（8.3）+ 长文件名（LFN），含已删除的 LFN 片段
  （首字节被 0xE5 覆盖时按盘上逆序重组）
- **簇链追踪**：防御式遍历，明确报告终止依据
- **签名辅助证据**：JPEG SOI/EOI、PDF `%PDF-`/`%%EOF` 仅用于调整置信度，
  绝不作为恢复成功的依据

## 输出

每个候选文件报告：

| 字段 | 含义 |
| --- | --- |
| `path` / `source_directory` | 目录来源（删除项首字符显示为 `_`） |
| `clusters` / `physical_offsets` | 簇列表及对应的物理偏移 |
| `declared_size` / `recoverable_bytes` | 目录项声明长度与链实际可交付长度 |
| `termination` | 终止依据（见下） |
| `issues` | 碎片、交叉链接、截断等问题列表 |
| `signature_evidence` | 签名匹配情况（仅辅助证据） |
| `confidence` | 置信度评分（high / medium / low） |

终止依据（`termination`）：

- `end_of_chain` — 正常到达 EOC 标记
- `loop_detected` — 簇链成环
- `bad_cluster` / `start_bad` — 遇到坏扇区标记
- `free_cluster` / `start_free` — 链中途指向未分配（零）表项
- `out_of_range` — 指针越出数据区

镜像级报告另包含：**FAT 副本差异**（逐字节比对所有 FAT 副本）、
**重叠/交叉链接簇**（同一簇被多个候选或活动文件声明）、
**坏扇区标记**列表。

## 用法

```bash
python -m fatcarver <image> [fat_copy_index]
```

或以库方式调用：

```python
from fatcarver import scan_image
report = scan_image("evidence.img")   # 返回 dict，可 JSON 序列化
```

## 测试

测试用代码在内存中构造小型 FAT12/16/32 镜像（`tests/imgbuild.py`），
覆盖：完整删除文件、碎片链、同名文件（不同目录）、循环链、伪造签名、
交叉链接、已分配簇复用、FAT 副本差异、坏扇区标记、长文件名、镜像只读性。

```bash
python -m unittest
```

## 布局

- `fatcarver/boot.py` — boot sector / BPB 解析与 FAT 类型判定
- `fatcarver/fat.py` — FAT 表访问、防御式簇链遍历、FAT 副本比对
- `fatcarver/directory.py` — 目录项与 LFN 解析
- `fatcarver/scanner.py` — 候选构建、重叠检测、置信度评分
- `fatcarver/signatures.py` — JPEG/PDF 签名辅助证据
- `fatcarver/image.py` — 只读镜像访问

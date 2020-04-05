---
title: 使用 Atom 与 Markdown 写文章
tags:
  - Atom
  - Markdown
categories: Others
keywords:
  - Atom
  - Markdown
translate_title: write-articles-using-atom-and-markdown
date: 2017-04-26 15:36:08
---

# 0x01 Atom
Atom 是 Github 推出的一个开源跨平台文本编辑器。具有简洁和直观的图形用户界面，支持 CSS、HTML、JavaScript 等网页编程语言。 并且支持宏和自动分屏等功能，还集成了文件管理器。同时，Atom 也支持 Markdown 语法，所以可以很方便地写 Hexo blog。

可以在官网下载[Atom](https://atom.io/)。

## 1. 常用快捷键
在File/Settings/Keybindiigns下定义了大量快捷键，常用快捷键如下:

| 快捷键                 | 功能                 |
|:------------------- |:------------------ |
| Crtl+Shift+M        | 开启Markdown实时预览     |
| Command+Shift+P     | 打开命令窗口，可以运行各种菜单功能  |
| Command + T         | 多文件切换              |
| Command + F         | 文件内查找和替换           |
| Command + Shift + F | 多文件查找和替换           |
| Command + [         | 对选中内容向左缩进          |
| Command + ]         | 对选中内容向右缩进          |
| Command + \         | 显示或隐藏目录树           |
| Crtl + m            | 括号之间/HTML tag之间等跳转 |

## 2. 插件
Atom 支持插件扩展，下面列举一些实用的插件。点击File/Settings/Install，输入相应的插件名称进行安装。

- Vim 模式(vim-mode-plus)
- 增强预览(markdown-preview-plus)   
需要关闭系统自带的 markdown-preview，Ctrl+Shift+M 打开预览窗口。
- 实时滚动预览(markdown-scroll-sync)   
预览窗口将跟随编辑界面的鼠标移动，可实时查看效果。
- 格式化代码(atom-beautify)   
- 表格编辑(markdown-table-editor)   
输入 table，然后按 Tab 键将自动输出表格样式。
- 导出pdf/png/jpeg/html(markdown-themeable-pdf)   
在文章编辑区域单击右键，Markdown to PDF。若要导出其它格式，在 File/Settings/packeages/markdown-themeable-pdf/Settings 中进行设置。
- 博客支持(markdown-Writer)

# 0x02 Markdown 常用语法
> Markdown 是一种轻量级标记语言，它允许人们 “易读易写的纯文本格式编写文档，然后转换成有效的XHTML(或者HTML)文档”。Markdown 最重要的设计是可读性，能直接在字面上的被阅读，而不用被一些格式化指令标记 (如 RTF 与 HTML)。 因此，它是现行电子邮件标记格式的惯例，虽然它也借鉴了很多早期的标记语言，如：setext、Texile、reStructuredText。 --- wikipedia

## 1. 换行
在行尾输入两个以上的空格然后回车。

## 2. 标题
在标题内容前输入特定数量的'#'来实现对应级别的HTML样式的标题(HTML提供六级标题)。   
```
# 这是 H1
## 这是 H2
###### 这是 H6
```

## 3. 区块引用
在引用内容的每行或者是段首加 '>'，引用块中可以根据层次加上不同数量的 '>'进行嵌套引用。 同时，引用区块内也可以使用其他的 Markdown 语法，包括标题、列表、代码区块等。   
```
> This is a blockquote with paragraphs.
```

## 4. 列表
Markdown 支持有序列表和无序列表。
无序列表使用 '\*'、'+' 或是 '-' 作为列表标记：   
```
-   Red   
-   Green   
-   Blue
```
有序列表则使用数字接着一个英文句点：
```
1.  Bird
2.  McHale
3.  Parish
```
当文章内容刚好行首出现数字-句点-空白时，不希望解析为有序列表，可以在句点前面加上反斜杠。

## 5. 代码块
在代码块的每行前面加 4 个空格或是 1 个制表符。
```
这是一个普通段落：
    这是一个代码区块。
```
当代码量较大时可以用三个反引号包围 \`\`\`。在代码块中添加一个可选的语言标识符,可以根据语法高亮显示，例如：  
```
''' C
void main() {
  printf ("Hello World!");
}
'''
```
如果要标记一小段行内代码，可以用反引号\`\`，例如：
```
Use the `printf()` function.
```

## 6. 分割线
在一行中用三个以上的 '\*' 或 '-' 来建立个分割线，在符号中间可以插入空格。下面是几种正确的写法：
```
* * *
***
*****
- - -
---------------------------------------
```

## 7. 链接
链接文字用 [方括号] 标记，方块括号后面圆括号中为网址链接（也可以是相对路径），网址后面双引号中的内容为链接的 title，例如：
```
This is [an example](http://example.com/ "Title") inline link.
[This link](http://example.net/) has no title attribute.
```

## 8. 强调
Markdown 使用 '\*' 或 '\_' 作为标记强调字词的符号。首尾各一个为斜体，首尾各两个为加粗。    
```
*single asterisks*
_single underscores_
**double asterisks**
__double underscores__
```

## 9. 设置字体
使用以下语法可设置字体的类型、大小和颜色。
```
<font face="微软雅黑">设置字体类型</font>
<font size=4>set font size</font>    
<font color=red> set font color </font>
```
效果如下：    
<font face="微软雅黑">设置字体类型</font>        
<font size=6>set font size</font>    
<font color=red> set font color </font>

## 10. 图片
Markdown 使用与链接相似的语法来标记图片，方括号内为图片的替代文字，圆括号内为图片地址，同样也可以加上 title。
```
![Alt text](/path/to/img.jpg "Title")
```

## 11. 自动链接
Markdown 支持以比较简短的自动链接形式来处理网址和电子邮件信箱，只要是用方括号包起来， Markdown 就会自动把它转成链接。例如：
```
<http://example.com/>
```

## 12. 表格
在安装 markdown-table-editor 插件之后可以很方便的编辑表格，输入table,按 Tab 键就会出现表格样式。注意在表格之前要空一行。
```
| Header One | Header Two |
|:---------- |:---------- |
| Item One   | Item Two   |
```
默认标题栏居中对齐，内容居左对齐。
-: 表示内容和标题栏靠右对齐，:- 表示内容和标题栏靠左对齐，:-: 表示内容和标题栏居中对齐。

# 0x03 插入图片
用 Markdown 写文章有个麻烦的地方就是不能直接插图片，通常需要将图片放在本地或者云上，然后在文章中通过图片链接（相对地址或网址）来插图片。为了节省 Blog 的空间，将图片上传到[七牛云](https://www.qiniu.com/)上。   

## 1. 注册账号并登录

## 2. 新建 buket
对象存储 > 新建存储空间，输入相关信息。   

## 3. 极简图床 Chrome 插件
使用极简图床可以绑定七牛云存储空间，然后可以通过拖拽的方式上传图片到云上。绑定七牛云需要空间名称、AK、SK 和域名。   
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586021035_26825806-file_1493208795361_1da.png)
## 4. 插入图片
在文章中使用以下语法插入图片。
```
![](image_link)

<div align=center>  # 图片居中
  <img src= "url"/>
</div >

![](image_link?imageView/3/w/400/h/400/q/100)   # 七牛云图片缩放，w：刻度，h：高度，q：图片质量
```

# 0x04 文章发布
在搭建好 Hexo Blog 之后，可以通过以下步骤新建并发布一篇新的文章。

## 1. 创建文章
执行下列命令来创建一篇新文章。
```
hexo new post <title>
```

## 2. 撰写文章
使用 Atom 和 Markdown 语法写文章内容。

## 3. 发布文章
首先需要生成静态文件，然后部署到Hexo中。
```
hexo clean  # 清除缓存文件 (db.json) 和已生成的静态文件 (public)
hexo g      # 生成静态文件
hexo d      # 部署网站
```

---
References:    
[1] [Markdown 官网语法说明](http://www.markdown.cn/)

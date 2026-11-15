mod dom_walker;
pub mod element_handler;
mod html_escape;
pub(crate) mod node_util;
pub mod options;
pub(crate) mod text_util;

use std::rc::Rc;

use dom_walker::walk_node;
use element_handler::{ElementHandler, ElementHandlers};
use html5ever::tendril::TendrilSink;
use html5ever::tree_builder::TreeBuilderOpts;
use html5ever::{Attribute, ParseOpts, parse_document};
// Export publicly, providing an interface to the
pub use markup5ever_rcdom::Node;
use markup5ever_rcdom::RcDom;
use options::Options;

use crate::element_handler::Handlers;

/// Convert HTML to Markdown.
///
/// Example:
///
/// ```
/// use htmd::convert;
///
/// let md = convert("<h1>Hello</h1>").unwrap();
/// assert_eq!("# Hello", md);
/// ```
pub fn convert(html: &str) -> Result<String, std::io::Error> {
    HtmlToMarkdown::new().convert(html)
}

/// The DOM element.
pub struct Element<'a> {
    /// The html5ever node of the element.
    pub node: &'a Rc<Node>,
    /// The tag name.
    pub tag: &'a str,
    /// The attribute list.
    pub attrs: &'a [Attribute],
    /// When true, this element's children were all translated using Markdown,
    /// not HTML. This is only needed in faithful translation mode (see the
    /// `Options`): for code blocks, translating a `<pre><code>` sequence to
    /// Markdown, not HTML, requires a Markdown translated `<code>` block;
    /// likewise, translating lists ((`<ol>`/`<ul>`)`<li>`) to Markdown requires
    /// all `<li>` elements are translated to Markdown.
    pub markdown_translated: bool,
    /// The number of handlers to skip for this element.
    pub(crate) skipped_handlers: usize,
}

/// The html-to-markdown converter.
///
/// # Example
/// ```
/// use htmd::{Element, HtmlToMarkdown};
///
/// // One-liner
/// let md = HtmlToMarkdown::new().convert("<h1>Hello</h1>").unwrap();
/// assert_eq!("# Hello", md);
///
/// // Or use the builder pattern
/// let converter = HtmlToMarkdown::builder()
///     .skip_tags(vec!["img"])
///     .build();
/// let md = converter.convert("<img src=\"https://example.com\">").unwrap();
/// // img is ignored
/// assert_eq!("", md);
/// ```
pub struct HtmlToMarkdown {
    handlers: ElementHandlers,
    scripting_enabled: bool,
}

impl Default for HtmlToMarkdown {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlToMarkdown {
    /// Create a new converter.
    pub fn new() -> Self {
        let options = Options::default();
        let handlers = ElementHandlers::new(options);
        Self {
            handlers,
            scripting_enabled: true,
        }
    }

    pub(crate) fn from_params(handlers: ElementHandlers, scripting_enabled: bool) -> Self {
        Self {
            handlers,
            scripting_enabled,
        }
    }

    /// Create a new [HtmlToMarkdownBuilder].
    pub fn builder() -> HtmlToMarkdownBuilder {
        HtmlToMarkdownBuilder::new()
    }

    /// Convert HTML to a DOM tree.
    pub fn html_to_tree(&self, html: &str) -> std::io::Result<Rc<Node>> {
        let dom = parse_document(
            RcDom::default(),
            ParseOpts {
                tree_builder: TreeBuilderOpts {
                    scripting_enabled: self.scripting_enabled,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .from_utf8()
        .read_from(&mut html.as_bytes())?;

        Ok(dom.document)
    }

    /// Convert a DOM tree to Markdown. For convenience, `Node` is re-exported;
    /// simply `use htmd::Node;` to access this type.
    pub fn tree_to_markdown(&self, tree: &Rc<Node>) -> String {
        let mut content = String::new();

        walk_node(tree, &mut content, &self.handlers, None, true, false);

        let mut content = content.trim_matches(|ch| ch == '\n').to_string();

        let mut append = String::new();
        for handler in &self.handlers.handlers {
            let Some(append_content) = handler.append() else {
                continue;
            };
            append.push_str(&append_content);
        }

        content.push_str(append.trim_end_matches('\n'));

        content
    }

    /// fuigo: whether `tree` holds more than `max_nodes` nodes or nests deeper than `max_depth`
    /// (the document is depth 0). Upstream has no bound on the tree this crate's own parser
    /// builds; a caller that bounded the page with another parser can check the tree it is
    /// about to convert. Iterative, linear in the tree size.
    pub fn tree_exceeds(tree: &Rc<Node>, max_depth: usize, max_nodes: usize) -> bool {
        let mut nodes = 0usize;
        let mut stack = vec![(Rc::clone(tree), 0usize)];
        while let Some((node, depth)) = stack.pop() {
            nodes += 1;
            if nodes > max_nodes || depth > max_depth {
                return true;
            }
            stack.extend(node.children.borrow().iter().map(|child| (Rc::clone(child), depth + 1)));
        }
        false
    }

    /// Convert HTML to Markdown.
    pub fn convert(&self, html: &str) -> std::io::Result<String> {
        Ok(self.tree_to_markdown(&self.html_to_tree(html)?))
    }
}

/// The [HtmlToMarkdown] builder for advanced configurations.
pub struct HtmlToMarkdownBuilder {
    handlers: ElementHandlers,
    scripting_enabled: bool,
}

impl Default for HtmlToMarkdownBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlToMarkdownBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        let options = Options::default();
        let handlers = ElementHandlers::new(options);
        Self {
            handlers,
            scripting_enabled: true,
        }
    }

    /// Set converting options.
    pub fn options(mut self, options: Options) -> Self {
        self.handlers.options = options;
        self
    }

    /// Skip a group of tags when converting.
    pub fn skip_tags(self, tags: Vec<&str>) -> Self {
        self.add_handler(tags, |_: &dyn Handlers, _: Element| None)
    }

    /// Apply a custom element handler for a group of tags.
    ///
    /// # Example
    ///
    /// ```
    /// use htmd::{Element, HtmlToMarkdownBuilder, element_handler::Handlers};
    ///
    /// let mut handlers = HtmlToMarkdownBuilder::new()
    ///    .add_handler(vec!["img"], |_handlers: &dyn Handlers, _: Element| {
    ///        // Skip the img tag when converting.
    ///        None
    ///    })
    ///    .add_handler(vec!["video"], |_handlers: &dyn Handlers, element: Element| {
    ///        // Handle the video tag.
    ///        todo!("Return some text to represent this video element.")
    ///    });
    /// ```
    pub fn add_handler<Handler>(mut self, tags: Vec<&str>, handler: Handler) -> Self
    where
        Handler: ElementHandler + 'static,
    {
        self.handlers.add_handler(tags, handler);
        self
    }

    /// Option for html5ever parsing. If true, the content of <noscript> tags will be converted to raw text.
    /// If false, the content of <noscript> tags will be parsed as normal DOM.
    pub fn scripting_enabled(mut self, enabled: bool) -> Self {
        self.scripting_enabled = enabled;
        self
    }

    /// Create a new [HtmlToMarkdown].
    pub fn build(self) -> HtmlToMarkdown {
        HtmlToMarkdown::from_params(self.handlers, self.scripting_enabled)
    }
}

#[cfg(test)]
mod fuigo_tree_bound_tests {
    use super::HtmlToMarkdown;

    #[test]
    fn tree_exceeds_counts_depth_and_nodes() {
        let converter = HtmlToMarkdown::new();
        let tree = converter.html_to_tree(&format!("{}x{}", "<div>".repeat(30), "</div>".repeat(30))).unwrap();
        // html, body and 30 divs, then the text node.
        assert!(!HtmlToMarkdown::tree_exceeds(&tree, 40, 1000));
        assert!(HtmlToMarkdown::tree_exceeds(&tree, 20, 1000));
        assert!(HtmlToMarkdown::tree_exceeds(&tree, 40, 10));
    }
}

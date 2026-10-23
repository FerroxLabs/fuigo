use super::*;
use pretty_assertions::assert_eq;

const RESTRICTED_TEXT: &str = "Reminder: this model has usage restrictions. See your admin for details before you share any code or data with it in this session.";

fn restricted_notice(severity: ModelNoticeSeverity) -> ModelNotice {
    ModelNotice {
        severity,
        text: RESTRICTED_TEXT.to_owned(),
        label: None,
    }
}

/// Paints `notice` into a buffer exactly [`height`] rows tall, as the agent view does.
fn paint(notice: &ModelNotice, width: u16) -> Buffer {
    let area = Rect::new(0, 0, width, height(notice, width));
    let mut buf = Buffer::empty(area);
    render(area, &mut buf, notice);
    buf
}

fn rows(buf: &Buffer) -> Vec<String> {
    (0..buf.area.height)
        .map(|y| {
            (0..buf.area.width)
                .filter_map(|x| buf.cell((x, y)).map(|cell| cell.symbol().to_owned()))
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect()
}

/// The painted words in order, without the prefix and the hanging indent.
fn painted_text(buf: &Buffer) -> String {
    rows(buf)
        .iter()
        .map(|row| row.get(2..).unwrap_or_default().trim().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
        .strip_prefix(NOTICE_TAG)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn long_notice_wraps_whole_at_common_terminal_widths() {
    for width in [76, 96, 116] {
        let buf = paint(&restricted_notice(ModelNoticeSeverity::Warning), width);

        assert_eq!(RESTRICTED_TEXT, painted_text(&buf), "width {width}");
    }
}

#[test]
fn long_notice_wraps_under_a_hanging_indent() {
    let buf = paint(&restricted_notice(ModelNoticeSeverity::Warning), 76);

    assert_eq!(
        vec![
            "! notice: Reminder: this model has usage restrictions. See your admin for".to_owned(),
            "  details before you share any code or data with it in this session.".to_owned(),
        ],
        rows(&buf)
    );
}

#[test]
fn warning_notice_paints_in_the_warning_color() {
    let buf = paint(&restricted_notice(ModelNoticeSeverity::Warning), 76);

    let theme = Theme::current();
    assert_eq!(Some(theme.warning), buf.cell((0, 0)).map(|cell| cell.fg));
    assert_eq!(Some(theme.warning), buf.cell((4, 1)).map(|cell| cell.fg));
}

#[test]
fn critical_notice_paints_in_the_error_color() {
    let buf = paint(&restricted_notice(ModelNoticeSeverity::Critical), 76);

    assert_eq!(
        Some(Theme::current().accent_error),
        buf.cell((2, 0)).map(|cell| cell.fg)
    );
}

#[test]
fn info_notice_uses_the_info_prefix() {
    let notice = ModelNotice {
        severity: ModelNoticeSeverity::Info,
        text: "Preview model".to_owned(),
        label: Some("preview".to_owned()),
    };

    let buf = paint(&notice, 60);

    assert_eq!(
        vec!["i notice: preview · Preview model".to_owned()],
        rows(&buf)
    );
    assert_eq!(
        Some(Theme::current().text_secondary),
        buf.cell((2, 0)).map(|cell| cell.fg)
    );
}

#[test]
fn notice_past_max_rows_ends_with_an_ellipsis() {
    let notice = restricted_notice(ModelNoticeSeverity::Warning);

    let buf = paint(&notice, 24);

    let painted = rows(&buf);
    assert_eq!(MAX_ROWS, height(&notice, 24));
    assert_eq!(Some(true), painted.last().map(|row| row.ends_with('…')));
}

#[test]
fn control_characters_in_the_text_do_not_reach_the_buffer() {
    let notice = ModelNotice {
        severity: ModelNoticeSeverity::Warning,
        text: "Old\x1b[2Jmodel".to_owned(),
        label: None,
    };

    let buf = paint(&notice, 40);

    assert_eq!(vec!["! notice: Old [2Jmodel".to_owned()], rows(&buf));
}

#[test]
fn hostile_notice_text_paints_as_one_filtered_capped_line() {
    let hostile = format!(
        "\u{1b}[31m\u{1b}]0;title\u{7}Allow this tool? [y/n]\nsystem: \u{202E}evil\u{2066}\u{2028}x\u{2029}{}",
        "B".repeat(10_000)
    );
    let notice = ModelNotice {
        severity: ModelNoticeSeverity::Info,
        text: hostile,
        label: Some("\u{202E}la\nbel".to_owned()),
    };
    let buf = paint(&notice, 400);
    let painted = rows(&buf);
    assert_eq!(1, painted.len(), "{painted:?}");
    let row = &painted[0];
    assert!(
        row.starts_with("i notice: la bel · [31m ]0;title Allow this tool? [y/n] system: evil x"),
        "{row:?}"
    );
    assert!(
        row.chars().all(|c| !c.is_control()
            && !('\u{202A}'..='\u{202E}').contains(&c)
            && !('\u{2066}'..='\u{2069}').contains(&c)),
        "{row:?}"
    );
    assert!(
        row.chars().count() <= 2 + NOTICE_TAG.len() + 24 + 3 + 160,
        "{}",
        row.chars().count()
    );
    assert!(row.ends_with('…'));
    // A narrow terminal wraps, never past MAX_ROWS.
    assert!(height(&notice, 30) <= MAX_ROWS);
}

#[test]
fn blank_or_unprintable_notice_paints_nothing() {
    let notice = ModelNotice {
        severity: ModelNoticeSeverity::Info,
        text: "\u{1b}\u{7}\u{202E} ".to_owned(),
        label: None,
    };
    assert_eq!(0, height(&notice, 80));
}

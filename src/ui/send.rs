use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::app::{AppState, MouseRegion, SendField, SendStage};
use crate::ui::Regions;
use crate::wallet::format_xmr;

/// Render the send XMR screen.
pub fn render_send(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    match &state.send_stage {
        SendStage::Entering => render_form(frame, area, state, regions),
        SendStage::Preparing(msg) => render_status(
            frame,
            area,
            " Preparing Transaction ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {}…", msg),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  This can take a moment while decoys are selected.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Press Esc to return to the dashboard (the send will continue).",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
        ),
        SendStage::Confirming {
            address,
            amount,
            fee,
            inputs,
        } => render_confirm(
            frame,
            area,
            address,
            *amount,
            *fee,
            *inputs,
            state.send_fee_priority.label(),
            regions,
        ),
        SendStage::Publishing => render_status(
            frame,
            area,
            " Publishing ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Broadcasting transaction to the network…",
                    Style::default().fg(Color::Yellow),
                )),
            ],
        ),
        SendStage::Done { tx_hash, fee } => render_status(
            frame,
            area,
            " Transaction Sent ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  ✓ Transaction published successfully",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Tx hash: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(tx_hash, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("  Fee:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(format_xmr(*fee), Style::default().fg(Color::Yellow)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "  It will confirm once mined. Press Enter to continue.",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
        ),
        SendStage::StoredForRetry { tx_hash, fee } => render_status(
            frame,
            area,
            " Relay Pending ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  The relay result was uncertain.",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  The exact signed transaction is saved and will be retried.",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(Span::styled(
                    "  Do not create a replacement; its inputs remain reserved.",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Tx hash: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(tx_hash, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("  Fee:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(format_xmr(*fee), Style::default().fg(Color::Yellow)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press Enter to continue.",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
        ),
        SendStage::Failed(msg) => render_status(
            frame,
            area,
            " Send Failed ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  ✗ {}", truncate(msg, 3)),
                    Style::default().fg(Color::Red),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press Enter to return to the form.",
                    Style::default().fg(Color::DarkGray),
                )),
            ],
        ),
    }
}

/// Render the sweep-all privacy acknowledgement above the send form.
pub fn render_sweep_warning(frame: &mut Frame, area: Rect, state: &AppState) {
    if !state.sweep_warning {
        return;
    }
    let popup = crate::ui::centered_rect(area, 70, 15);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Sweep-all spends every unlocked output in one transaction.",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  If those outputs came from different senders or subaddresses,"),
        Line::from("  consolidating them can link those payment histories on-chain."),
        Line::from(""),
        Line::from("  The recipient receives the entire unlocked balance minus fee."),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Y] Continue sweep   ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "[N] Cancel",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Sweep-all privacy warning ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// Keep long error messages readable in the status pane.
fn truncate(msg: &str, max_lines: usize) -> String {
    let mut out = String::new();
    for (i, line) in msg.lines().enumerate() {
        if i >= max_lines {
            out.push('…');
            break;
        }
        if i > 0 {
            out.push_str("\n  ");
        }
        out.push_str(line);
    }
    out
}

fn render_form(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(14), // Send form
            Constraint::Min(6),     // Address book
            Constraint::Length(8),  // Fee estimate / info
        ])
        .split(area);

    // Clickable field rows (inside the form block's border):
    // line 1 = Recipient, line 3 = Amount.
    let form = chunks[0];
    let inner_x = form.x + 1;
    let inner_width = form.width.saturating_sub(2);
    for (line, field) in [(1u16, SendField::Address), (3u16, SendField::Amount)] {
        let y = form.y + 1 + line;
        if y < form.bottom().saturating_sub(1) && inner_width > 0 {
            regions.push((
                Rect::new(inner_x, y, inner_width, 1),
                MouseRegion::SendField(field),
            ));
        }
    }

    let form_block = Block::default()
        .title(" Send XMR ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let address_focused = state.send_field == SendField::Address;
    let amount_focused = state.send_field == SendField::Amount;

    let address_display = if state.send_address.is_empty() {
        Span::styled(
            "<enter recipient address>",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(&state.send_address, Style::default().fg(Color::White))
    };
    let amount_display = if state.send_amount.is_empty() {
        Span::styled(
            "<enter amount in XMR>",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(&state.send_amount, Style::default().fg(Color::Green))
    };

    let address_label = if address_focused {
        "▶ Recipient [D]: "
    } else {
        "  Recipient [D]: "
    };
    let amount_label = if amount_focused {
        "▶ Amount [A]:    "
    } else {
        "  Amount [A]:    "
    };

    let available = format_xmr(state.balance.unlocked);

    let form_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                address_label,
                Style::default().fg(if address_focused {
                    Color::Yellow
                } else {
                    Color::Cyan
                }),
            ),
            address_display,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                amount_label,
                Style::default().fg(if amount_focused {
                    Color::Yellow
                } else {
                    Color::Cyan
                }),
            ),
            amount_display,
            Span::styled(" XMR", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Available: ", Style::default().fg(Color::DarkGray)),
            Span::styled(available, Style::default().fg(Color::Green)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Tab/↑/↓ switch fields • [D]/[A] jump • [M] max • [P] fee priority",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  Enter builds the transaction • Esc cancels • ←/→ switch screens",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let form_widget = Paragraph::new(form_lines).block(form_block);
    frame.render_widget(form_widget, chunks[0]);

    render_book_pane(frame, chunks[1], state, regions);

    let fee_block = Block::default()
        .title(" Fee Info ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let fee_lines = vec![
        Line::from(vec![
            Span::styled("  Priority: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.send_fee_priority.label(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Est. Fee: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "calculated from the daemon's fee rate",
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  You'll review the exact fee before anything is broadcast.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let fee_widget = Paragraph::new(fee_lines).block(fee_block);
    frame.render_widget(fee_widget, chunks[2]);
}

/// The address-book pane on the send screen: saved recipients, selectable
/// to fill the address field.
fn render_book_pane(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    let focused = state.send_field == SendField::Book;
    let title = if focused {
        " Address Book [B] (↑↓ select • Enter use • [N] add • [X] delete) "
    } else {
        " Address Book [B] "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        });

    // Clicking anywhere in the pane focuses it; rows (pushed after, so they
    // win the reverse hit-test) fill the address directly.
    regions.push((
        Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            area.height.saturating_sub(2),
        ),
        MouseRegion::SendField(SendField::Book),
    ));

    let inner_height = area.height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();
    if state.address_book.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No saved recipients.",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "  Press [B] then [N] to save the recipient above for reuse.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        // Keep the selected row inside the visible window.
        let selected = state.book_selected.min(state.address_book.len() - 1);
        let start = if selected >= inner_height && inner_height > 0 {
            selected + 1 - inner_height
        } else {
            0
        };
        for (i, entry) in state.address_book.iter().enumerate().skip(start) {
            if lines.len() >= inner_height {
                break;
            }
            let y = area.y + 1 + lines.len() as u16;
            if y < area.bottom().saturating_sub(1) {
                regions.push((
                    Rect::new(area.x + 1, y, area.width.saturating_sub(2), 1),
                    MouseRegion::AddressBookRow(i),
                ));
            }
            let is_sel = focused && i == selected;
            let marker = if is_sel { " ▶ " } else { "   " };
            let style = if is_sel {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            // Label column (padded/truncated), then a middle-truncated
            // address so start and checksum tail stay visible.
            let label: String = entry.label.chars().take(14).collect();
            let label_width = 15usize;
            let addr_budget = (area.width as usize)
                .saturating_sub(3 + label_width + 2)
                .max(16);
            let addr = if entry.address.len() > addr_budget {
                let keep = addr_budget.saturating_sub(1) / 2;
                format!(
                    "{}…{}",
                    &entry.address[..keep],
                    &entry.address[entry.address.len() - (addr_budget - 2 - keep)..]
                )
            } else {
                entry.address.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(format!("{label:<label_width$}"), style),
                Span::styled(addr, style),
            ]));
        }
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

#[allow(clippy::too_many_arguments)]
fn render_confirm(
    frame: &mut Frame,
    area: Rect,
    address: &str,
    amount: u64,
    fee: u64,
    inputs: usize,
    priority: &str,
    regions: &mut Regions,
) {
    // Register the [Y] / [N] buttons as click targets. They sit on the last
    // content line (line index 11 inside the block border).
    let button_y = area.y + 1 + 11;
    if button_y < area.bottom().saturating_sub(1) {
        let inner_x = area.x + 1;
        let yes_width = 25u16.min(area.width.saturating_sub(2));
        if yes_width > 0 {
            regions.push((
                Rect::new(inner_x, button_y, yes_width, 1),
                MouseRegion::ConfirmYes,
            ));
        }
        let no_x = inner_x + yes_width;
        let no_width = 10u16.min(area.right().saturating_sub(1).saturating_sub(no_x));
        if no_width > 0 {
            regions.push((
                Rect::new(no_x, button_y, no_width, 1),
                MouseRegion::ConfirmNo,
            ));
        }
    }

    let block = Block::default()
        .title(" Confirm Transaction ")
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    // Wrap the address across lines so it is FULLY visible on narrow
    // terminals (95 chars for mainnet standard addresses).
    let addr_mid = address.len() / 2;
    let (addr_a, addr_b) = address.split_at(addr_mid);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  To (verify every character):",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("    {addr_a}"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            format!("    {addr_b}"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(vec![
            Span::styled("  Amount:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_xmr(amount),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Fee:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}  ({} priority)", format_xmr(fee), priority),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Inputs:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} (ring size 16)", inputs),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Total:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_xmr(amount.saturating_add(fee)),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Review carefully — transactions cannot be reversed.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Y] Sign & broadcast   ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "[N] Cancel",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

fn render_status(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line>) {
    let block = Block::default()
        .title(format!(" {} ", title.trim()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

/// Render the address-book "add entry" modal, if open.
pub fn render_book_modal(frame: &mut Frame, area: Rect, state: &AppState) {
    let crate::app::BookModal::Adding {
        label,
        address,
        focus,
        error,
    } = &state.book_modal
    else {
        return;
    };
    use crate::app::BookField;

    let popup = crate::ui::centered_rect(area, 64, 13);
    frame.render_widget(Clear, popup);

    let label_focused = *focus == BookField::Label;
    let address_focused = *focus == BookField::Address;
    let cursor = |focused: bool| {
        if focused {
            Span::styled("\u{2588}", Style::default().fg(Color::Cyan))
        } else {
            Span::raw("")
        }
    };
    let field_style = |focused: bool| {
        if focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        }
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                if label_focused {
                    "\u{25b6} Label:   "
                } else {
                    "  Label:   "
                },
                Style::default().fg(if label_focused {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }),
            ),
            Span::styled(label.as_str(), field_style(label_focused)),
            cursor(label_focused),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                if address_focused {
                    "\u{25b6} Address: "
                } else {
                    "  Address: "
                },
                Style::default().fg(if address_focused {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }),
            ),
            Span::styled(address.as_str(), field_style(address_focused)),
            cursor(address_focused),
        ]),
        Line::from(""),
    ];
    if let Some(error) = error {
        lines.push(Line::from(Span::styled(
            format!("  \u{2717} {error}"),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Tab: switch field    Enter: save    Esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Save recipient ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}

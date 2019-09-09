#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "xhci.h"
#include "xhci-trace.h"

dma_addr_t xhci_trb_virt_to_dma(struct xhci_segment *seg,
		union xhci_trb *trb)
{
	unsigned long segment_offset;

	if (!seg || !trb || trb < seg->trbs)
		return 0;
	 
	segment_offset = trb - seg->trbs;
	if (segment_offset >= TRBS_PER_SEGMENT)
		return 0;
	return seg->dma + (segment_offset * sizeof(*trb));
}

static bool last_trb_on_last_seg(struct xhci_hcd *xhci, struct xhci_ring *ring,
		struct xhci_segment *seg, union xhci_trb *trb)
{
	if (ring == xhci->event_ring)
		return (trb == &seg->trbs[TRBS_PER_SEGMENT]) &&
			(seg->next == xhci->event_ring->first_seg);
	else
		return le32_to_cpu(trb->link.control) & LINK_TOGGLE;
}

static int last_trb(struct xhci_hcd *xhci, struct xhci_ring *ring,
		struct xhci_segment *seg, union xhci_trb *trb)
{
	if (ring == xhci->event_ring)
		return trb == &seg->trbs[TRBS_PER_SEGMENT];
	else
		return TRB_TYPE_LINK_LE32(trb->link.control);
}

static int enqueue_is_link_trb(struct xhci_ring *ring)
{
	struct xhci_link_trb *link = &ring->enqueue->link;
	return TRB_TYPE_LINK_LE32(link->control);
}

static void next_trb(struct xhci_hcd *xhci,
		struct xhci_ring *ring,
		struct xhci_segment **seg,
		union xhci_trb **trb)
{
	if (last_trb(xhci, ring, *seg, *trb)) {
		*seg = (*seg)->next;
		*trb = ((*seg)->trbs);
	} else {
		(*trb)++;
	}
}

static void inc_deq(struct xhci_hcd *xhci, struct xhci_ring *ring)
{
	ring->deq_updates++;

	if (ring->type != TYPE_EVENT &&
			!last_trb(xhci, ring, ring->deq_seg, ring->dequeue))
		ring->num_trbs_free++;

	do {
		 
		if (last_trb(xhci, ring, ring->deq_seg, ring->dequeue)) {
			if (ring->type == TYPE_EVENT &&
					last_trb_on_last_seg(xhci, ring,
						ring->deq_seg, ring->dequeue)) {
				ring->cycle_state ^= 1;
			}
			ring->deq_seg = ring->deq_seg->next;
			ring->dequeue = ring->deq_seg->trbs;
		} else {
			ring->dequeue++;
		}
	} while (last_trb(xhci, ring, ring->deq_seg, ring->dequeue));
}

static void inc_enq(struct xhci_hcd *xhci, struct xhci_ring *ring,
			bool more_trbs_coming)
{
	u32 chain;
	union xhci_trb *next;

	chain = le32_to_cpu(ring->enqueue->generic.field[3]) & TRB_CHAIN;
	 
	if (ring->type != TYPE_EVENT &&
			!last_trb(xhci, ring, ring->enq_seg, ring->enqueue))
		ring->num_trbs_free--;
	next = ++(ring->enqueue);

	ring->enq_updates++;
	 
	while (last_trb(xhci, ring, ring->enq_seg, next)) {
		if (ring->type != TYPE_EVENT) {
			 
			if (!chain && !more_trbs_coming)
				break;

			if (!(ring->type == TYPE_ISOC &&
					(xhci->quirks & XHCI_AMD_0x96_HOST))
						&& !xhci_link_trb_quirk(xhci)) {
				next->link.control &=
					cpu_to_le32(~TRB_CHAIN);
				next->link.control |=
					cpu_to_le32(chain);
			}
			 
			wmb();
			next->link.control ^= cpu_to_le32(TRB_CYCLE);

			if (last_trb_on_last_seg(xhci, ring, ring->enq_seg, next)) {
				ring->cycle_state ^= 1;
			}
		}
		ring->enq_seg = ring->enq_seg->next;
		ring->enqueue = ring->enq_seg->trbs;
		next = ring->enqueue;
	}
}

static inline int room_on_ring(struct xhci_hcd *xhci, struct xhci_ring *ring,
		unsigned int num_trbs)
{
	int num_trbs_in_deq_seg;

	if (ring->num_trbs_free < num_trbs)
		return 0;

	if (ring->type != TYPE_COMMAND && ring->type != TYPE_EVENT) {
		num_trbs_in_deq_seg = ring->dequeue - ring->deq_seg->trbs;
		if (ring->num_trbs_free < num_trbs + num_trbs_in_deq_seg)
			return 0;
	}

	return 1;
}

void xhci_ring_cmd_db(struct xhci_hcd *xhci)
{
	if (!(xhci->cmd_ring_state & CMD_RING_STATE_RUNNING))
		return;

	xhci_dbg(xhci, "// Ding dong!\n");
	writel(DB_VALUE_HOST, &xhci->dba->doorbell[0]);
	 
	readl(&xhci->dba->doorbell[0]);
}

static bool xhci_mod_cmd_timer(struct xhci_hcd *xhci, unsigned long delay)
{
	return mod_delayed_work(system_wq, &xhci->cmd_timer, delay);
}

static struct xhci_command *xhci_next_queued_cmd(struct xhci_hcd *xhci)
{
	return list_first_entry_or_null(&xhci->cmd_list, struct xhci_command,
					cmd_list);
}

static void xhci_handle_stopped_cmd_ring(struct xhci_hcd *xhci,
					 struct xhci_command *cur_cmd)
{
	struct xhci_command *i_cmd;
	u32 cycle_state;

	list_for_each_entry(i_cmd, &xhci->cmd_list, cmd_list) {

		if (i_cmd->status != COMP_CMD_ABORT)
			continue;

		i_cmd->status = COMP_CMD_STOP;

		xhci_dbg(xhci, "Turn aborted command %p to no-op\n",
			 i_cmd->command_trb);
		 
		cycle_state = le32_to_cpu(
			i_cmd->command_trb->generic.field[3]) &	TRB_CYCLE;
		 
		i_cmd->command_trb->generic.field[0] = 0;
		i_cmd->command_trb->generic.field[1] = 0;
		i_cmd->command_trb->generic.field[2] = 0;
		i_cmd->command_trb->generic.field[3] = cpu_to_le32(
			TRB_TYPE(TRB_CMD_NOOP) | cycle_state);

	}

	xhci->cmd_ring_state = CMD_RING_STATE_RUNNING;

	if ((xhci->cmd_ring->dequeue != xhci->cmd_ring->enqueue) &&
	    !(xhci->xhc_state & XHCI_STATE_DYING)) {
		xhci->current_cmd = cur_cmd;
		xhci_mod_cmd_timer(xhci, XHCI_CMD_DEFAULT_TIMEOUT);
		xhci_ring_cmd_db(xhci);
	}
}

static int xhci_abort_cmd_ring(struct xhci_hcd *xhci, unsigned long flags)
{
	u64 temp_64;
	int ret;

	xhci_dbg(xhci, "Abort command ring\n");

	reinit_completion(&xhci->cmd_ring_stop_completion);

	temp_64 = xhci_read_64(xhci, &xhci->op_regs->cmd_ring);
	xhci_write_64(xhci, temp_64 | CMD_RING_ABORT,
			&xhci->op_regs->cmd_ring);

	ret = xhci_handshake(&xhci->op_regs->cmd_ring,
			CMD_RING_RUNNING, 0, 5 * 1000 * 1000);
	if (ret < 0) {
		 
		xhci_write_64(xhci, temp_64 | CMD_RING_ABORT,
			      &xhci->op_regs->cmd_ring);
		udelay(1000);
		ret = xhci_handshake(&xhci->op_regs->cmd_ring,
				     CMD_RING_RUNNING, 0, 3 * 1000 * 1000);
		if (ret < 0) {
			xhci_err(xhci, "Stopped the command ring failed, "
				 "maybe the host is dead\n");
			xhci->xhc_state |= XHCI_STATE_DYING;
			xhci_quiesce(xhci);
			xhci_halt(xhci);
			return -ESHUTDOWN;
		}
	}
	 
	spin_unlock_irqrestore(&xhci->lock, flags);
	ret = wait_for_completion_timeout(&xhci->cmd_ring_stop_completion,
					  msecs_to_jiffies(2000));
	spin_lock_irqsave(&xhci->lock, flags);
	if (!ret) {
		xhci_dbg(xhci, "No stop event for abort, ring start fail?\n");
		xhci_cleanup_command_queue(xhci);
	} else {
		xhci_handle_stopped_cmd_ring(xhci, xhci_next_queued_cmd(xhci));
	}

	return 0;
}

void xhci_ring_ep_doorbell(struct xhci_hcd *xhci,
		unsigned int slot_id,
		unsigned int ep_index,
		unsigned int stream_id)
{
	__le32 __iomem *db_addr = &xhci->dba->doorbell[slot_id];
	struct xhci_virt_ep *ep = &xhci->devs[slot_id]->eps[ep_index];
	unsigned int ep_state = ep->ep_state;

	if ((ep_state & EP_HALT_PENDING) || (ep_state & SET_DEQ_PENDING) ||
	    (ep_state & EP_HALTED))
		return;
	writel(DB_VALUE(ep_index, stream_id), db_addr);
	 
}

static void ring_doorbell_for_active_rings(struct xhci_hcd *xhci,
		unsigned int slot_id,
		unsigned int ep_index)
{
	unsigned int stream_id;
	struct xhci_virt_ep *ep;

	ep = &xhci->devs[slot_id]->eps[ep_index];

	if (!(ep->ep_state & EP_HAS_STREAMS)) {
		if (ep->ring && !(list_empty(&ep->ring->td_list)))
			xhci_ring_ep_doorbell(xhci, slot_id, ep_index, 0);
		return;
	}

	for (stream_id = 1; stream_id < ep->stream_info->num_streams;
			stream_id++) {
		struct xhci_stream_info *stream_info = ep->stream_info;
		if (!list_empty(&stream_info->stream_rings[stream_id]->td_list))
			xhci_ring_ep_doorbell(xhci, slot_id, ep_index,
						stream_id);
	}
}

static struct xhci_ring *xhci_triad_to_transfer_ring(struct xhci_hcd *xhci,
		unsigned int slot_id, unsigned int ep_index,
		unsigned int stream_id)
{
	struct xhci_virt_ep *ep;

	ep = &xhci->devs[slot_id]->eps[ep_index];
	 
	if (!(ep->ep_state & EP_HAS_STREAMS))
		return ep->ring;

	if (stream_id == 0) {
		xhci_warn(xhci,
				"WARN: Slot ID %u, ep index %u has streams, "
				"but URB has no stream ID.\n",
				slot_id, ep_index);
		return NULL;
	}

	if (stream_id < ep->stream_info->num_streams)
		return ep->stream_info->stream_rings[stream_id];

	xhci_warn(xhci,
			"WARN: Slot ID %u, ep index %u has "
			"stream IDs 1 to %u allocated, "
			"but stream ID %u is requested.\n",
			slot_id, ep_index,
			ep->stream_info->num_streams - 1,
			stream_id);
	return NULL;
}

static struct xhci_ring *xhci_urb_to_transfer_ring(struct xhci_hcd *xhci,
		struct urb *urb)
{
	return xhci_triad_to_transfer_ring(xhci, urb->dev->slot_id,
		xhci_get_endpoint_index(&urb->ep->desc), urb->stream_id);
}

void xhci_find_new_dequeue_state(struct xhci_hcd *xhci,
		unsigned int slot_id, unsigned int ep_index,
		unsigned int stream_id, struct xhci_td *cur_td,
		struct xhci_dequeue_state *state)
{
	struct xhci_virt_device *dev = xhci->devs[slot_id];
	struct xhci_virt_ep *ep = &dev->eps[ep_index];
	struct xhci_ring *ep_ring;
	struct xhci_segment *new_seg;
	union xhci_trb *new_deq;
	dma_addr_t addr;
	u64 hw_dequeue;
	bool cycle_found = false;
	bool td_last_trb_found = false;

	ep_ring = xhci_triad_to_transfer_ring(xhci, slot_id,
			ep_index, stream_id);
	if (!ep_ring) {
		xhci_warn(xhci, "WARN can't find new dequeue state "
				"for invalid stream ID %u.\n",
				stream_id);
		return;
	}

	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"Finding endpoint context");
	 
	if (ep->ep_state & EP_HAS_STREAMS) {
		struct xhci_stream_ctx *ctx =
			&ep->stream_info->stream_ctx_array[stream_id];
		hw_dequeue = le64_to_cpu(ctx->stream_ring);
	} else {
		struct xhci_ep_ctx *ep_ctx
			= xhci_get_ep_ctx(xhci, dev->out_ctx, ep_index);
		hw_dequeue = le64_to_cpu(ep_ctx->deq);
	}

	new_seg = ep_ring->deq_seg;
	new_deq = ep_ring->dequeue;
	state->new_cycle_state = hw_dequeue & 0x1;

	do {
		if (!cycle_found && xhci_trb_virt_to_dma(new_seg, new_deq)
		    == (dma_addr_t)(hw_dequeue & ~0xf)) {
			cycle_found = true;
			if (td_last_trb_found)
				break;
		}
		if (new_deq == cur_td->last_trb)
			td_last_trb_found = true;

		if (cycle_found &&
		    TRB_TYPE_LINK_LE32(new_deq->generic.field[3]) &&
		    new_deq->generic.field[3] & cpu_to_le32(LINK_TOGGLE))
			state->new_cycle_state ^= 0x1;

		next_trb(xhci, ep_ring, &new_seg, &new_deq);

		if (new_deq == ep->ring->dequeue) {
			xhci_err(xhci, "Error: Failed finding new dequeue state\n");
			state->new_deq_seg = NULL;
			state->new_deq_ptr = NULL;
			return;
		}

	} while (!cycle_found || !td_last_trb_found);

	state->new_deq_seg = new_seg;
	state->new_deq_ptr = new_deq;

	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"Cycle state = 0x%x", state->new_cycle_state);

	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"New dequeue segment = %p (virtual)",
			state->new_deq_seg);
	addr = xhci_trb_virt_to_dma(state->new_deq_seg, state->new_deq_ptr);
	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"New dequeue pointer = 0x%llx (DMA)",
			(unsigned long long) addr);
}

static void td_to_noop(struct xhci_hcd *xhci, struct xhci_ring *ep_ring,
		struct xhci_td *cur_td, bool flip_cycle)
{
	struct xhci_segment *cur_seg;
	union xhci_trb *cur_trb;

	for (cur_seg = cur_td->start_seg, cur_trb = cur_td->first_trb;
			true;
			next_trb(xhci, ep_ring, &cur_seg, &cur_trb)) {
		if (TRB_TYPE_LINK_LE32(cur_trb->generic.field[3])) {
			 
			cur_trb->generic.field[3] &= cpu_to_le32(~TRB_CHAIN);
			 
			if (flip_cycle)
				cur_trb->generic.field[3] ^=
					cpu_to_le32(TRB_CYCLE);
			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"Cancel (unchain) link TRB");
			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"Address = %p (0x%llx dma); "
					"in seg %p (0x%llx dma)",
					cur_trb,
					(unsigned long long)xhci_trb_virt_to_dma(cur_seg, cur_trb),
					cur_seg,
					(unsigned long long)cur_seg->dma);
		} else {
			cur_trb->generic.field[0] = 0;
			cur_trb->generic.field[1] = 0;
			cur_trb->generic.field[2] = 0;
			 
			cur_trb->generic.field[3] &= cpu_to_le32(TRB_CYCLE);
			 
			if (flip_cycle && cur_trb != cur_td->first_trb &&
					cur_trb != cur_td->last_trb)
				cur_trb->generic.field[3] ^=
					cpu_to_le32(TRB_CYCLE);
			cur_trb->generic.field[3] |= cpu_to_le32(
				TRB_TYPE(TRB_TR_NOOP));
			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"TRB to noop at offset 0x%llx",
					(unsigned long long)
					xhci_trb_virt_to_dma(cur_seg, cur_trb));
		}
		if (cur_trb == cur_td->last_trb)
			break;
	}
}

static void xhci_stop_watchdog_timer_in_irq(struct xhci_hcd *xhci,
		struct xhci_virt_ep *ep)
{
	ep->ep_state &= ~EP_HALT_PENDING;
	 
	if (del_timer(&ep->stop_cmd_timer))
		ep->stop_cmds_pending--;
}

static void xhci_giveback_urb_in_irq(struct xhci_hcd *xhci,
		struct xhci_td *cur_td, int status)
{
	struct usb_hcd *hcd;
	struct urb	*urb;
	struct urb_priv	*urb_priv;

	urb = cur_td->urb;
	urb_priv = urb->hcpriv;
	urb_priv->td_cnt++;
	hcd = bus_to_hcd(urb->dev->bus);

	if (urb_priv->td_cnt == urb_priv->length) {
		if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS) {
			xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs--;
			if (xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs	== 0) {
				if (xhci->quirks & XHCI_AMD_PLL_FIX)
					usb_amd_quirk_pll_enable();
			}
		}
		usb_hcd_unlink_urb_from_ep(hcd, urb);

		spin_unlock(&xhci->lock);
		usb_hcd_giveback_urb(hcd, urb, status);
		xhci_urb_free_priv(urb_priv);
		spin_lock(&xhci->lock);
	}
}

static void xhci_handle_cmd_stop_ep(struct xhci_hcd *xhci, int slot_id,
		union xhci_trb *trb, struct xhci_event_cmd *event)
{
	unsigned int ep_index;
	struct xhci_ring *ep_ring;
	struct xhci_virt_ep *ep;
	struct list_head *entry;
	struct xhci_td *cur_td = NULL;
	struct xhci_td *last_unlinked_td;

	struct xhci_dequeue_state deq_state;

	if (unlikely(TRB_TO_SUSPEND_PORT(le32_to_cpu(trb->generic.field[3])))) {
		if (!xhci->devs[slot_id])
			xhci_warn(xhci, "Stop endpoint command "
				"completion for disabled slot %u\n",
				slot_id);
		return;
	}

	memset(&deq_state, 0, sizeof(deq_state));
	ep_index = TRB_TO_EP_INDEX(le32_to_cpu(trb->generic.field[3]));
	ep = &xhci->devs[slot_id]->eps[ep_index];

	if (list_empty(&ep->cancelled_td_list)) {
		xhci_stop_watchdog_timer_in_irq(xhci, ep);
		ep->stopped_td = NULL;
		ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
		return;
	}

	list_for_each(entry, &ep->cancelled_td_list) {
		cur_td = list_entry(entry, struct xhci_td, cancelled_td_list);
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"Removing canceled TD starting at 0x%llx (dma).",
				(unsigned long long)xhci_trb_virt_to_dma(
					cur_td->start_seg, cur_td->first_trb));
		ep_ring = xhci_urb_to_transfer_ring(xhci, cur_td->urb);
		if (!ep_ring) {
			 
			xhci_warn(xhci, "WARN Cancelled URB %p "
					"has invalid stream ID %u.\n",
					cur_td->urb,
					cur_td->urb->stream_id);
			goto remove_finished_td;
		}
		 
		if (cur_td == ep->stopped_td)
			xhci_find_new_dequeue_state(xhci, slot_id, ep_index,
					cur_td->urb->stream_id,
					cur_td, &deq_state);
		else
			td_to_noop(xhci, ep_ring, cur_td, false);
remove_finished_td:
		 
		list_del_init(&cur_td->td_list);
	}
	last_unlinked_td = cur_td;
	xhci_stop_watchdog_timer_in_irq(xhci, ep);

	if (deq_state.new_deq_ptr && deq_state.new_deq_seg) {
		xhci_queue_new_dequeue_state(xhci, slot_id, ep_index,
				ep->stopped_td->urb->stream_id, &deq_state);
		xhci_ring_cmd_db(xhci);
	} else {
		 
		ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
	}

	ep->stopped_td = NULL;

	do {
		cur_td = list_entry(ep->cancelled_td_list.next,
				struct xhci_td, cancelled_td_list);
		list_del_init(&cur_td->cancelled_td_list);

		xhci_giveback_urb_in_irq(xhci, cur_td, 0);

		if (xhci->xhc_state & XHCI_STATE_DYING)
			return;
	} while (cur_td != last_unlinked_td);

}

static void xhci_kill_ring_urbs(struct xhci_hcd *xhci, struct xhci_ring *ring)
{
	struct xhci_td *cur_td;

	while (!list_empty(&ring->td_list)) {
		cur_td = list_first_entry(&ring->td_list,
				struct xhci_td, td_list);
		list_del_init(&cur_td->td_list);
		if (!list_empty(&cur_td->cancelled_td_list))
			list_del_init(&cur_td->cancelled_td_list);
		xhci_giveback_urb_in_irq(xhci, cur_td, -ESHUTDOWN);
	}
}

static void xhci_kill_endpoint_urbs(struct xhci_hcd *xhci,
		int slot_id, int ep_index)
{
	struct xhci_td *cur_td;
	struct xhci_virt_ep *ep;
	struct xhci_ring *ring;

	ep = &xhci->devs[slot_id]->eps[ep_index];
	if ((ep->ep_state & EP_HAS_STREAMS) ||
			(ep->ep_state & EP_GETTING_NO_STREAMS)) {
		int stream_id;

		for (stream_id = 0; stream_id < ep->stream_info->num_streams;
				stream_id++) {
			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"Killing URBs for slot ID %u, ep index %u, stream %u",
					slot_id, ep_index, stream_id + 1);
			xhci_kill_ring_urbs(xhci,
					ep->stream_info->stream_rings[stream_id]);
		}
	} else {
		ring = ep->ring;
		if (!ring)
			return;
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"Killing URBs for slot ID %u, ep index %u",
				slot_id, ep_index);
		xhci_kill_ring_urbs(xhci, ring);
	}
	while (!list_empty(&ep->cancelled_td_list)) {
		cur_td = list_first_entry(&ep->cancelled_td_list,
				struct xhci_td, cancelled_td_list);
		list_del_init(&cur_td->cancelled_td_list);
		xhci_giveback_urb_in_irq(xhci, cur_td, -ESHUTDOWN);
	}
}

void xhci_stop_endpoint_command_watchdog(unsigned long arg)
{
	struct xhci_hcd *xhci;
	struct xhci_virt_ep *ep;
	int ret, i, j;
	unsigned long flags;

	ep = (struct xhci_virt_ep *) arg;
	xhci = ep->xhci;

	spin_lock_irqsave(&xhci->lock, flags);

	ep->stop_cmds_pending--;
	if (!(ep->stop_cmds_pending == 0 && (ep->ep_state & EP_HALT_PENDING))) {
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
				"Stop EP timer ran, but no command pending, "
				"exiting.");
		spin_unlock_irqrestore(&xhci->lock, flags);
		return;
	}

	xhci_warn(xhci, "xHCI host not responding to stop endpoint command.\n");
	xhci_warn(xhci, "Assuming host is dying, halting host.\n");
	 
	xhci->xhc_state |= XHCI_STATE_DYING;
	 
	xhci_quiesce(xhci);
	spin_unlock_irqrestore(&xhci->lock, flags);

	ret = xhci_halt(xhci);

	spin_lock_irqsave(&xhci->lock, flags);
	if (ret < 0) {
		 
		xhci_warn(xhci, "Non-responsive xHCI host is not halting.\n");
		xhci_warn(xhci, "Completing active URBs anyway.\n");
		 
	}
	for (i = 0; i < MAX_HC_SLOTS; i++) {
		if (!xhci->devs[i])
			continue;
		for (j = 0; j < 31; j++)
			xhci_kill_endpoint_urbs(xhci, i, j);
	}
	spin_unlock_irqrestore(&xhci->lock, flags);
	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"Calling usb_hc_died()");
	usb_hc_died(xhci_to_hcd(xhci));
	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"xHCI host controller is dead.");
}

static void update_ring_for_set_deq_completion(struct xhci_hcd *xhci,
		struct xhci_virt_device *dev,
		struct xhci_ring *ep_ring,
		unsigned int ep_index)
{
	union xhci_trb *dequeue_temp;
	int num_trbs_free_temp;
	bool revert = false;

	num_trbs_free_temp = ep_ring->num_trbs_free;
	dequeue_temp = ep_ring->dequeue;

	if (last_trb(xhci, ep_ring, ep_ring->deq_seg, ep_ring->dequeue)) {
		ep_ring->deq_seg = ep_ring->deq_seg->next;
		ep_ring->dequeue = ep_ring->deq_seg->trbs;
	}

	while (ep_ring->dequeue != dev->eps[ep_index].queued_deq_ptr) {
		 
		ep_ring->num_trbs_free++;
		ep_ring->dequeue++;
		if (last_trb(xhci, ep_ring, ep_ring->deq_seg,
				ep_ring->dequeue)) {
			if (ep_ring->dequeue ==
					dev->eps[ep_index].queued_deq_ptr)
				break;
			ep_ring->deq_seg = ep_ring->deq_seg->next;
			ep_ring->dequeue = ep_ring->deq_seg->trbs;
		}
		if (ep_ring->dequeue == dequeue_temp) {
			revert = true;
			break;
		}
	}

	if (revert) {
		xhci_dbg(xhci, "Unable to find new dequeue pointer\n");
		ep_ring->num_trbs_free = num_trbs_free_temp;
	}
}

static void xhci_handle_cmd_set_deq(struct xhci_hcd *xhci, int slot_id,
		union xhci_trb *trb, u32 cmd_comp_code)
{
	unsigned int ep_index;
	unsigned int stream_id;
	struct xhci_ring *ep_ring;
	struct xhci_virt_device *dev;
	struct xhci_virt_ep *ep;
	struct xhci_ep_ctx *ep_ctx;
	struct xhci_slot_ctx *slot_ctx;

	ep_index = TRB_TO_EP_INDEX(le32_to_cpu(trb->generic.field[3]));
	stream_id = TRB_TO_STREAM_ID(le32_to_cpu(trb->generic.field[2]));
	dev = xhci->devs[slot_id];
	ep = &dev->eps[ep_index];

	ep_ring = xhci_stream_id_to_ring(dev, ep_index, stream_id);
	if (!ep_ring) {
		xhci_warn(xhci, "WARN Set TR deq ptr command for freed stream ID %u\n",
				stream_id);
		 
		goto cleanup;
	}

	ep_ctx = xhci_get_ep_ctx(xhci, dev->out_ctx, ep_index);
	slot_ctx = xhci_get_slot_ctx(xhci, dev->out_ctx);

	if (cmd_comp_code != COMP_SUCCESS) {
		unsigned int ep_state;
		unsigned int slot_state;

		switch (cmd_comp_code) {
		case COMP_TRB_ERR:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd invalid because of stream ID configuration\n");
			break;
		case COMP_CTX_STATE:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd failed due to incorrect slot or ep state.\n");
			ep_state = le32_to_cpu(ep_ctx->ep_info);
			ep_state &= EP_STATE_MASK;
			slot_state = le32_to_cpu(slot_ctx->dev_state);
			slot_state = GET_SLOT_STATE(slot_state);
			xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
					"Slot state = %u, EP state = %u",
					slot_state, ep_state);
			break;
		case COMP_EBADSLT:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd failed because slot %u was not enabled.\n",
					slot_id);
			break;
		default:
			xhci_warn(xhci, "WARN Set TR Deq Ptr cmd with unknown completion code of %u.\n",
					cmd_comp_code);
			break;
		}
		 
	} else {
		u64 deq;
		 
		if (ep->ep_state & EP_HAS_STREAMS) {
			struct xhci_stream_ctx *ctx =
				&ep->stream_info->stream_ctx_array[stream_id];
			deq = le64_to_cpu(ctx->stream_ring) & SCTX_DEQ_MASK;
		} else {
			deq = le64_to_cpu(ep_ctx->deq) & ~EP_CTX_CYCLE_MASK;
		}
		xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
			"Successful Set TR Deq Ptr cmd, deq = @%08llx", deq);
		if (xhci_trb_virt_to_dma(ep->queued_deq_seg,
					 ep->queued_deq_ptr) == deq) {
			 
			update_ring_for_set_deq_completion(xhci, dev,
				ep_ring, ep_index);
		} else {
			xhci_warn(xhci, "Mismatch between completed Set TR Deq Ptr command & xHCI internal state.\n");
			xhci_warn(xhci, "ep deq seg = %p, deq ptr = %p\n",
				  ep->queued_deq_seg, ep->queued_deq_ptr);
		}
	}

cleanup:
	dev->eps[ep_index].ep_state &= ~SET_DEQ_PENDING;
	dev->eps[ep_index].queued_deq_seg = NULL;
	dev->eps[ep_index].queued_deq_ptr = NULL;
	 
	ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
}

static void xhci_handle_cmd_reset_ep(struct xhci_hcd *xhci, int slot_id,
		union xhci_trb *trb, u32 cmd_comp_code)
{
	unsigned int ep_index;

	ep_index = TRB_TO_EP_INDEX(le32_to_cpu(trb->generic.field[3]));
	 
	xhci_dbg_trace(xhci, trace_xhci_dbg_reset_ep,
		"Ignoring reset ep completion code of %u", cmd_comp_code);

	if (xhci->quirks & XHCI_RESET_EP_QUIRK) {
		struct xhci_command *command;
		command = xhci_alloc_command(xhci, false, false, GFP_ATOMIC);
		if (!command) {
			xhci_warn(xhci, "WARN Cannot submit cfg ep: ENOMEM\n");
			return;
		}
		xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"Queueing configure endpoint command");
		xhci_queue_configure_endpoint(xhci, command,
				xhci->devs[slot_id]->in_ctx->dma, slot_id,
				false);
		xhci_ring_cmd_db(xhci);
	} else {
		 
		xhci->devs[slot_id]->eps[ep_index].ep_state &= ~EP_HALTED;
	}
}

static void xhci_handle_cmd_enable_slot(struct xhci_hcd *xhci, int slot_id,
		u32 cmd_comp_code)
{
	if (cmd_comp_code == COMP_SUCCESS)
		xhci->slot_id = slot_id;
	else
		xhci->slot_id = 0;
}

static void xhci_handle_cmd_disable_slot(struct xhci_hcd *xhci, int slot_id)
{
	struct xhci_virt_device *virt_dev;

	virt_dev = xhci->devs[slot_id];
	if (!virt_dev)
		return;
	if (xhci->quirks & XHCI_EP_LIMIT_QUIRK)
		 
		xhci_free_device_endpoint_resources(xhci, virt_dev, true);
	xhci_free_virt_device(xhci, slot_id);
}

static void xhci_handle_cmd_config_ep(struct xhci_hcd *xhci, int slot_id,
		struct xhci_event_cmd *event, u32 cmd_comp_code)
{
	struct xhci_virt_device *virt_dev;
	struct xhci_input_control_ctx *ctrl_ctx;
	unsigned int ep_index;
	unsigned int ep_state;
	u32 add_flags, drop_flags;

	virt_dev = xhci->devs[slot_id];
	ctrl_ctx = xhci_get_input_control_ctx(virt_dev->in_ctx);
	if (!ctrl_ctx) {
		xhci_warn(xhci, "Could not get input context, bad type.\n");
		return;
	}

	add_flags = le32_to_cpu(ctrl_ctx->add_flags);
	drop_flags = le32_to_cpu(ctrl_ctx->drop_flags);
	 
	ep_index = xhci_last_valid_endpoint(add_flags) - 1;

	if (xhci->quirks & XHCI_RESET_EP_QUIRK &&
			ep_index != (unsigned int) -1 &&
			add_flags - SLOT_FLAG == drop_flags) {
		ep_state = virt_dev->eps[ep_index].ep_state;
		if (!(ep_state & EP_HALTED))
			return;
		xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
				"Completed config ep cmd - "
				"last ep index = %d, state = %d",
				ep_index, ep_state);
		 
		virt_dev->eps[ep_index].ep_state &= ~EP_HALTED;
		ring_doorbell_for_active_rings(xhci, slot_id, ep_index);
		return;
	}
	return;
}

static void xhci_handle_cmd_reset_dev(struct xhci_hcd *xhci, int slot_id,
		struct xhci_event_cmd *event)
{
	xhci_dbg(xhci, "Completed reset device command.\n");
	if (!xhci->devs[slot_id])
		xhci_warn(xhci, "Reset device command completion "
				"for disabled slot %u\n", slot_id);
}

static void xhci_handle_cmd_nec_get_fw(struct xhci_hcd *xhci,
		struct xhci_event_cmd *event)
{
	if (!(xhci->quirks & XHCI_NEC_HOST)) {
		xhci->error_bitmask |= 1 << 6;
		return;
	}
	xhci_dbg_trace(xhci, trace_xhci_dbg_quirks,
			"NEC firmware version %2x.%02x",
			NEC_FW_MAJOR(le32_to_cpu(event->status)),
			NEC_FW_MINOR(le32_to_cpu(event->status)));
}

static void xhci_complete_del_and_free_cmd(struct xhci_command *cmd, u32 status)
{
	list_del(&cmd->cmd_list);

	if (cmd->completion) {
		cmd->status = status;
		complete(cmd->completion);
	} else {
		kfree(cmd);
	}
}

void xhci_cleanup_command_queue(struct xhci_hcd *xhci)
{
	struct xhci_command *cur_cmd, *tmp_cmd;
	list_for_each_entry_safe(cur_cmd, tmp_cmd, &xhci->cmd_list, cmd_list)
		xhci_complete_del_and_free_cmd(cur_cmd, COMP_CMD_ABORT);
}

void xhci_handle_command_timeout(struct work_struct *work)
{
	struct xhci_hcd *xhci;
	int ret;
	unsigned long flags;
	u64 hw_ring_state;

	xhci = container_of(to_delayed_work(work), struct xhci_hcd, cmd_timer);

	spin_lock_irqsave(&xhci->lock, flags);

	if (!xhci->current_cmd || delayed_work_pending(&xhci->cmd_timer)) {
		spin_unlock_irqrestore(&xhci->lock, flags);
		return;
	}
	 
	xhci->current_cmd->status = COMP_CMD_ABORT;

	hw_ring_state = xhci_read_64(xhci, &xhci->op_regs->cmd_ring);
	if ((xhci->cmd_ring_state & CMD_RING_STATE_RUNNING) &&
	    (hw_ring_state & CMD_RING_RUNNING))  {
		 
		xhci->cmd_ring_state = CMD_RING_STATE_ABORTED;
		xhci_dbg(xhci, "Command timeout\n");
		ret = xhci_abort_cmd_ring(xhci, flags);
		if (unlikely(ret == -ESHUTDOWN)) {
			xhci_err(xhci, "Abort command ring failed\n");
			xhci_cleanup_command_queue(xhci);
			spin_unlock_irqrestore(&xhci->lock, flags);
			usb_hc_died(xhci_to_hcd(xhci)->primary_hcd);
			xhci_dbg(xhci, "xHCI host controller is dead.\n");

			return;
		}

		goto time_out_completed;
	}

	if (xhci->xhc_state & XHCI_STATE_REMOVING) {
		xhci_dbg(xhci, "host removed, ring start fail?\n");
		xhci_cleanup_command_queue(xhci);

		goto time_out_completed;
	}

	xhci_dbg(xhci, "Command timeout on stopped ring\n");
	xhci_handle_stopped_cmd_ring(xhci, xhci->current_cmd);

time_out_completed:
	spin_unlock_irqrestore(&xhci->lock, flags);
	return;
}

static void handle_cmd_completion(struct xhci_hcd *xhci,
		struct xhci_event_cmd *event)
{
	int slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	u64 cmd_dma;
	dma_addr_t cmd_dequeue_dma;
	u32 cmd_comp_code;
	union xhci_trb *cmd_trb;
	struct xhci_command *cmd;
	u32 cmd_type;

	cmd_dma = le64_to_cpu(event->cmd_trb);
	cmd_trb = xhci->cmd_ring->dequeue;
	cmd_dequeue_dma = xhci_trb_virt_to_dma(xhci->cmd_ring->deq_seg,
			cmd_trb);
	 
	if (cmd_dequeue_dma == 0) {
		xhci->error_bitmask |= 1 << 4;
		return;
	}
	 
	if (cmd_dma != (u64) cmd_dequeue_dma) {
		xhci->error_bitmask |= 1 << 5;
		return;
	}

	cmd = list_entry(xhci->cmd_list.next, struct xhci_command, cmd_list);

	cancel_delayed_work(&xhci->cmd_timer);

	trace_xhci_cmd_completion(cmd_trb, (struct xhci_generic_trb *) event);

	cmd_comp_code = GET_COMP_CODE(le32_to_cpu(event->status));

	if (cmd_comp_code == COMP_CMD_STOP) {
		complete_all(&xhci->cmd_ring_stop_completion);
		return;
	}

	if (cmd->command_trb != xhci->cmd_ring->dequeue) {
		xhci_err(xhci,
			 "Command completion event does not match command\n");
		return;
	}

	if (cmd_comp_code == COMP_CMD_ABORT) {
		xhci->cmd_ring_state = CMD_RING_STATE_STOPPED;
		if (cmd->status == COMP_CMD_ABORT) {
			if (xhci->current_cmd == cmd)
				xhci->current_cmd = NULL;
			goto event_handled;
		}
	}

	cmd_type = TRB_FIELD_TO_TYPE(le32_to_cpu(cmd_trb->generic.field[3]));
	switch (cmd_type) {
	case TRB_ENABLE_SLOT:
		xhci_handle_cmd_enable_slot(xhci, slot_id, cmd_comp_code);
		break;
	case TRB_DISABLE_SLOT:
		xhci_handle_cmd_disable_slot(xhci, slot_id);
		break;
	case TRB_CONFIG_EP:
		if (!cmd->completion)
			xhci_handle_cmd_config_ep(xhci, slot_id, event,
						  cmd_comp_code);
		break;
	case TRB_EVAL_CONTEXT:
		break;
	case TRB_ADDR_DEV:
		break;
	case TRB_STOP_RING:
		WARN_ON(slot_id != TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3])));
		xhci_handle_cmd_stop_ep(xhci, slot_id, cmd_trb, event);
		break;
	case TRB_SET_DEQ:
		WARN_ON(slot_id != TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3])));
		xhci_handle_cmd_set_deq(xhci, slot_id, cmd_trb, cmd_comp_code);
		break;
	case TRB_CMD_NOOP:
		 
		if (cmd->status == COMP_CMD_STOP)
			cmd_comp_code = COMP_CMD_STOP;
		break;
	case TRB_RESET_EP:
		WARN_ON(slot_id != TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3])));
		xhci_handle_cmd_reset_ep(xhci, slot_id, cmd_trb, cmd_comp_code);
		break;
	case TRB_RESET_DEV:
		 
		slot_id = TRB_TO_SLOT_ID(
				le32_to_cpu(cmd_trb->generic.field[3]));
		xhci_handle_cmd_reset_dev(xhci, slot_id, event);
		break;
	case TRB_NEC_GET_FW:
		xhci_handle_cmd_nec_get_fw(xhci, event);
		break;
	default:
		 
		xhci->error_bitmask |= 1 << 6;
		break;
	}

	if (cmd->cmd_list.next != &xhci->cmd_list) {
		xhci->current_cmd = list_entry(cmd->cmd_list.next,
					       struct xhci_command, cmd_list);
		xhci_mod_cmd_timer(xhci, XHCI_CMD_DEFAULT_TIMEOUT);
	} else if (xhci->current_cmd == cmd) {
		xhci->current_cmd = NULL;
	}

event_handled:
	xhci_complete_del_and_free_cmd(cmd, cmd_comp_code);

	inc_deq(xhci, xhci->cmd_ring);
}

static void handle_vendor_event(struct xhci_hcd *xhci,
		union xhci_trb *event)
{
	u32 trb_type;

	trb_type = TRB_FIELD_TO_TYPE(le32_to_cpu(event->generic.field[3]));
	xhci_dbg(xhci, "Vendor specific event TRB type = %u\n", trb_type);
	if (trb_type == TRB_NEC_CMD_COMP && (xhci->quirks & XHCI_NEC_HOST))
		handle_cmd_completion(xhci, &event->event_cmd);
}

#ifdef MY_ABC_HERE
static void xhci_giveback_error_urb(struct xhci_hcd *xhci,
				int slot_id)
{
	struct xhci_virt_device *virt_dev;
	int i;

	virt_dev = xhci->devs[slot_id];
	for (i = LAST_EP_INDEX; i > 0; i--) {
			struct xhci_virt_ep *ep = &virt_dev->eps[i];
			struct xhci_ring *ring = ep->ring;
			if (!ring)
					continue;

			if (!list_empty(&ring->td_list)) {
					struct xhci_td *cur_td = list_first_entry(&ring->td_list,
							struct xhci_td,
							td_list);
					list_del_init(&cur_td->td_list);
					if (!list_empty(&cur_td->cancelled_td_list))
							list_del_init(&cur_td->cancelled_td_list);
					xhci_giveback_urb_in_irq(xhci, cur_td, -EPROTO);
			}
	}
}
#endif  

static unsigned int find_faked_portnum_from_hw_portnum(struct usb_hcd *hcd,
		struct xhci_hcd *xhci, u32 port_id)
{
	unsigned int i;
	unsigned int num_similar_speed_ports = 0;

	for (i = 0; i < (port_id - 1); i++) {
		u8 port_speed = xhci->port_array[i];

		if (port_speed == 0 || port_speed == DUPLICATE_ENTRY)
			continue;

		if ((port_speed == 0x03) == (hcd->speed >= HCD_USB3))
			num_similar_speed_ports++;
	}
	return num_similar_speed_ports;
}

static void handle_device_notification(struct xhci_hcd *xhci,
		union xhci_trb *event)
{
	u32 slot_id;
	struct usb_device *udev;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->generic.field[3]));
	if (!xhci->devs[slot_id]) {
		xhci_warn(xhci, "Device Notification event for "
				"unused slot %u\n", slot_id);
		return;
	}

	xhci_dbg(xhci, "Device Wake Notification event for slot ID %u\n",
			slot_id);
	udev = xhci->devs[slot_id]->udev;
	if (udev && udev->parent)
		usb_wakeup_notification(udev->parent, udev->portnum);
}

static void handle_port_status(struct xhci_hcd *xhci,
		union xhci_trb *event)
{
	struct usb_hcd *hcd;
	u32 port_id;
	u32 temp, temp1;
	int max_ports;
	int slot_id;
	unsigned int faked_port_index;
	u8 major_revision;
	struct xhci_bus_state *bus_state;
	__le32 __iomem **port_array;
	bool bogus_port_status = false;

	if (GET_COMP_CODE(le32_to_cpu(event->generic.field[2])) != COMP_SUCCESS) {
		xhci_warn(xhci, "WARN: xHC returned failed port status event\n");
		xhci->error_bitmask |= 1 << 8;
	}
	port_id = GET_PORT_ID(le32_to_cpu(event->generic.field[0]));
	xhci_dbg(xhci, "Port Status Change Event for port %d\n", port_id);

	max_ports = HCS_MAX_PORTS(xhci->hcs_params1);
	if ((port_id <= 0) || (port_id > max_ports)) {
		xhci_warn(xhci, "Invalid port id %d\n", port_id);
		inc_deq(xhci, xhci->event_ring);
		return;
	}

	major_revision = xhci->port_array[port_id - 1];

	hcd = xhci_to_hcd(xhci);
	if ((major_revision == 0x03) != (hcd->speed >= HCD_USB3))
		hcd = xhci->shared_hcd;

	if (major_revision == 0) {
		xhci_warn(xhci, "Event for port %u not in "
				"Extended Capabilities, ignoring.\n",
				port_id);
		bogus_port_status = true;
		goto cleanup;
	}
	if (major_revision == DUPLICATE_ENTRY) {
		xhci_warn(xhci, "Event for port %u duplicated in"
				"Extended Capabilities, ignoring.\n",
				port_id);
		bogus_port_status = true;
		goto cleanup;
	}

	bus_state = &xhci->bus_state[hcd_index(hcd)];
	if (hcd->speed >= HCD_USB3)
		port_array = xhci->usb3_ports;
	else
		port_array = xhci->usb2_ports;
	 
	faked_port_index = find_faked_portnum_from_hw_portnum(hcd, xhci,
			port_id);

	temp = readl(port_array[faked_port_index]);
	if (hcd->state == HC_STATE_SUSPENDED) {
		xhci_dbg(xhci, "resume root hub\n");
		usb_hcd_resume_root_hub(hcd);
	}

	if (hcd->speed >= HCD_USB3 && (temp & PORT_PLS_MASK) == XDEV_INACTIVE)
		bus_state->port_remote_wakeup &= ~(1 << faked_port_index);

	if ((temp & PORT_PLC) && (temp & PORT_PLS_MASK) == XDEV_RESUME) {
		xhci_dbg(xhci, "port resume event for port %d\n", port_id);

		temp1 = readl(&xhci->op_regs->command);
		if (!(temp1 & CMD_RUN)) {
			xhci_warn(xhci, "xHC is not running.\n");
			goto cleanup;
		}

		if (DEV_SUPERSPEED_ANY(temp)) {
			xhci_dbg(xhci, "remote wake SS port %d\n", port_id);
			 
			bus_state->port_remote_wakeup |= 1 << faked_port_index;
			xhci_test_and_clear_bit(xhci, port_array,
					faked_port_index, PORT_PLC);
			xhci_set_link_state(xhci, port_array, faked_port_index,
						XDEV_U0);
			 
			bogus_port_status = true;
			goto cleanup;
		} else if (!test_bit(faked_port_index,
				     &bus_state->resuming_ports)) {
			xhci_dbg(xhci, "resume HS port %d\n", port_id);
			bus_state->resume_done[faked_port_index] = jiffies +
				msecs_to_jiffies(USB_RESUME_TIMEOUT);
			set_bit(faked_port_index, &bus_state->resuming_ports);
			mod_timer(&hcd->rh_timer,
				  bus_state->resume_done[faked_port_index]);
			 
		}
	}

#ifdef MY_ABC_HERE
	if (!(temp & PORT_CONNECT) &&
			(temp & PORT_WRC)) {
			slot_id = xhci_find_slot_id_by_port(hcd, xhci,
					faked_port_index + 1);
			if (slot_id && xhci->devs[slot_id]) {
					xhci_warn(xhci, "device is plugged out, empty URBs\n");
					xhci->devs[slot_id]->disconnected = true;
					xhci_giveback_error_urb(xhci, slot_id);
			}
	}
#endif  

	if ((temp & PORT_PLC) && (temp & PORT_PLS_MASK) == XDEV_U0 &&
			DEV_SUPERSPEED_ANY(temp)) {
		xhci_dbg(xhci, "resume SS port %d finished\n", port_id);
		 
		slot_id = xhci_find_slot_id_by_port(hcd, xhci,
				faked_port_index + 1);
		if (slot_id && xhci->devs[slot_id])
			xhci_ring_device(xhci, slot_id);
		if (bus_state->port_remote_wakeup & (1 << faked_port_index)) {
			bus_state->port_remote_wakeup &=
				~(1 << faked_port_index);
			xhci_test_and_clear_bit(xhci, port_array,
					faked_port_index, PORT_PLC);
			usb_wakeup_notification(hcd->self.root_hub,
					faked_port_index + 1);
			bogus_port_status = true;
			goto cleanup;
		}
	}

	if (!DEV_SUPERSPEED_ANY(temp) &&
			test_and_clear_bit(faked_port_index,
				&bus_state->rexit_ports)) {
		complete(&bus_state->rexit_done[faked_port_index]);
		bogus_port_status = true;
		goto cleanup;
	}

	if (hcd->speed < HCD_USB3)
		xhci_test_and_clear_bit(xhci, port_array, faked_port_index,
					PORT_PLC);

cleanup:
	 
	inc_deq(xhci, xhci->event_ring);

	if (bogus_port_status)
		return;

	xhci_dbg(xhci, "%s: starting port polling.\n", __func__);
	set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	spin_unlock(&xhci->lock);
	 
	usb_hcd_poll_rh_status(hcd);
	spin_lock(&xhci->lock);
}

struct xhci_segment *trb_in_td(struct xhci_hcd *xhci,
		struct xhci_segment *start_seg,
		union xhci_trb	*start_trb,
		union xhci_trb	*end_trb,
		dma_addr_t	suspect_dma,
		bool		debug)
{
	dma_addr_t start_dma;
	dma_addr_t end_seg_dma;
	dma_addr_t end_trb_dma;
	struct xhci_segment *cur_seg;

	start_dma = xhci_trb_virt_to_dma(start_seg, start_trb);
	cur_seg = start_seg;

	do {
		if (start_dma == 0)
			return NULL;
		 
		end_seg_dma = xhci_trb_virt_to_dma(cur_seg,
				&cur_seg->trbs[TRBS_PER_SEGMENT - 1]);
		 
		end_trb_dma = xhci_trb_virt_to_dma(cur_seg, end_trb);

		if (debug)
			xhci_warn(xhci,
				"Looking for event-dma %016llx trb-start %016llx trb-end %016llx seg-start %016llx seg-end %016llx\n",
				(unsigned long long)suspect_dma,
				(unsigned long long)start_dma,
				(unsigned long long)end_trb_dma,
				(unsigned long long)cur_seg->dma,
				(unsigned long long)end_seg_dma);

		if (end_trb_dma > 0) {
			 
			if (start_dma <= end_trb_dma) {
				if (suspect_dma >= start_dma && suspect_dma <= end_trb_dma)
					return cur_seg;
			} else {
				 
				if ((suspect_dma >= start_dma &&
							suspect_dma <= end_seg_dma) ||
						(suspect_dma >= cur_seg->dma &&
						 suspect_dma <= end_trb_dma))
					return cur_seg;
			}
			return NULL;
		} else {
			 
			if (suspect_dma >= start_dma && suspect_dma <= end_seg_dma)
				return cur_seg;
		}
		cur_seg = cur_seg->next;
		start_dma = xhci_trb_virt_to_dma(cur_seg, &cur_seg->trbs[0]);
	} while (cur_seg != start_seg);

	return NULL;
}

static void xhci_cleanup_halted_endpoint(struct xhci_hcd *xhci,
		unsigned int slot_id, unsigned int ep_index,
		unsigned int stream_id,
		struct xhci_td *td, union xhci_trb *event_trb)
{
	struct xhci_virt_ep *ep = &xhci->devs[slot_id]->eps[ep_index];
	struct xhci_command *command;
	command = xhci_alloc_command(xhci, false, false, GFP_ATOMIC);
	if (!command)
		return;

	ep->ep_state |= EP_HALTED;
	ep->stopped_stream = stream_id;

	xhci_queue_reset_ep(xhci, command, slot_id, ep_index);
	xhci_cleanup_stalled_ring(xhci, ep_index, td);

	ep->stopped_stream = 0;

	xhci_ring_cmd_db(xhci);
}

static int xhci_requires_manual_halt_cleanup(struct xhci_hcd *xhci,
		struct xhci_ep_ctx *ep_ctx,
		unsigned int trb_comp_code)
{
	 
	if (trb_comp_code == COMP_TX_ERR ||
			trb_comp_code == COMP_BABBLE ||
			trb_comp_code == COMP_SPLIT_ERR)
		 
		if ((ep_ctx->ep_info & cpu_to_le32(EP_STATE_MASK)) ==
		    cpu_to_le32(EP_STATE_HALTED))
			return 1;

	return 0;
}

int xhci_is_vendor_info_code(struct xhci_hcd *xhci, unsigned int trb_comp_code)
{
	if (trb_comp_code >= 224 && trb_comp_code <= 255) {
		 
		xhci_dbg(xhci, "Vendor defined info completion code %u\n",
				trb_comp_code);
		xhci_dbg(xhci, "Treating code as success.\n");
		return 1;
	}
	return 0;
}

static int finish_td(struct xhci_hcd *xhci, struct xhci_td *td,
	union xhci_trb *event_trb, struct xhci_transfer_event *event,
	struct xhci_virt_ep *ep, int *status, bool skip)
{
	struct xhci_virt_device *xdev;
	struct xhci_ring *ep_ring;
	unsigned int slot_id;
	int ep_index;
	struct urb *urb = NULL;
	struct xhci_ep_ctx *ep_ctx;
	int ret = 0;
	struct urb_priv	*urb_priv;
	u32 trb_comp_code;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	xdev = xhci->devs[slot_id];
	ep_index = TRB_TO_EP_ID(le32_to_cpu(event->flags)) - 1;
	ep_ring = xhci_dma_to_transfer_ring(ep, le64_to_cpu(event->buffer));
	ep_ctx = xhci_get_ep_ctx(xhci, xdev->out_ctx, ep_index);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));

	if (skip)
		goto td_cleanup;

	if (trb_comp_code == COMP_STOP_INVAL ||
			trb_comp_code == COMP_STOP ||
			trb_comp_code == COMP_STOP_SHORT) {
		 
		ep->stopped_td = td;
		return 0;
	}
	if (trb_comp_code == COMP_STALL ||
		xhci_requires_manual_halt_cleanup(xhci, ep_ctx,
						trb_comp_code)) {
		 
		xhci_cleanup_halted_endpoint(xhci, slot_id, ep_index,
					ep_ring->stream_id, td, event_trb);
	} else {
		 
		while (ep_ring->dequeue != td->last_trb)
			inc_deq(xhci, ep_ring);
		inc_deq(xhci, ep_ring);
	}

td_cleanup:
	 
	urb = td->urb;
	urb_priv = urb->hcpriv;

	if (urb->actual_length > urb->transfer_buffer_length) {
		xhci_warn(xhci, "URB transfer length is wrong, xHC issue? req. len = %u, act. len = %u\n",
			urb->transfer_buffer_length,
			urb->actual_length);
		urb->actual_length = 0;
		if (td->urb->transfer_flags & URB_SHORT_NOT_OK)
			*status = -EREMOTEIO;
		else
			*status = 0;
	}
	list_del_init(&td->td_list);
	 
	if (!list_empty(&td->cancelled_td_list))
		list_del_init(&td->cancelled_td_list);

	urb_priv->td_cnt++;
	 
	if (urb_priv->td_cnt == urb_priv->length) {
		ret = 1;
		if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS) {
			xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs--;
			if (xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs == 0) {
				if (xhci->quirks & XHCI_AMD_PLL_FIX)
					usb_amd_quirk_pll_enable();
			}
		}
	}

	return ret;
}

static int process_ctrl_td(struct xhci_hcd *xhci, struct xhci_td *td,
	union xhci_trb *event_trb, struct xhci_transfer_event *event,
	struct xhci_virt_ep *ep, int *status)
{
	struct xhci_virt_device *xdev;
	struct xhci_ring *ep_ring;
	unsigned int slot_id;
	int ep_index;
	struct xhci_ep_ctx *ep_ctx;
	u32 trb_comp_code;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	xdev = xhci->devs[slot_id];
	ep_index = TRB_TO_EP_ID(le32_to_cpu(event->flags)) - 1;
	ep_ring = xhci_dma_to_transfer_ring(ep, le64_to_cpu(event->buffer));
	ep_ctx = xhci_get_ep_ctx(xhci, xdev->out_ctx, ep_index);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		if (event_trb == ep_ring->dequeue) {
			xhci_warn(xhci, "WARN: Success on ctrl setup TRB "
					"without IOC set??\n");
			*status = -ESHUTDOWN;
		} else if (event_trb != td->last_trb) {
			xhci_warn(xhci, "WARN: Success on ctrl data TRB "
					"without IOC set??\n");
			*status = -ESHUTDOWN;
		} else {
			*status = 0;
		}
		break;
	case COMP_SHORT_TX:
		if (td->urb->transfer_flags & URB_SHORT_NOT_OK)
			*status = -EREMOTEIO;
		else
			*status = 0;
		break;
	case COMP_STOP_SHORT:
		if (event_trb == ep_ring->dequeue || event_trb == td->last_trb)
			xhci_warn(xhci, "WARN: Stopped Short Packet on ctrl setup or status TRB\n");
		else
			td->urb->actual_length =
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));

		return finish_td(xhci, td, event_trb, event, ep, status, false);
	case COMP_STOP:
		 
		if (event_trb != ep_ring->dequeue && event_trb != td->last_trb)
			td->urb->actual_length =
				td->urb->transfer_buffer_length -
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
		 
	case COMP_STOP_INVAL:
		return finish_td(xhci, td, event_trb, event, ep, status, false);
	default:
		if (!xhci_requires_manual_halt_cleanup(xhci,
					ep_ctx, trb_comp_code))
			break;
		xhci_dbg(xhci, "TRB error code %u, "
				"halted endpoint index = %u\n",
				trb_comp_code, ep_index);
		 
	case COMP_STALL:
		 
		if (event_trb != ep_ring->dequeue &&
				event_trb != td->last_trb)
			td->urb->actual_length =
				td->urb->transfer_buffer_length -
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
		else if (!td->urb_length_set)
			td->urb->actual_length = 0;

		return finish_td(xhci, td, event_trb, event, ep, status, false);
	}
	 
	if (event_trb != ep_ring->dequeue) {
		 
		if (event_trb == td->last_trb) {
			if (td->urb_length_set) {
				 
				if ((*status == -EINPROGRESS || *status == 0) &&
						(td->urb->transfer_flags
						 & URB_SHORT_NOT_OK))
					 
					*status = -EREMOTEIO;
			} else {
				td->urb->actual_length =
					td->urb->transfer_buffer_length;
			}
		} else {
			 
			td->urb_length_set = true;
			td->urb->actual_length =
				td->urb->transfer_buffer_length -
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
			xhci_dbg(xhci, "Waiting for status "
					"stage event\n");
			return 0;
		}
	}

	return finish_td(xhci, td, event_trb, event, ep, status, false);
}

static int process_isoc_td(struct xhci_hcd *xhci, struct xhci_td *td,
	union xhci_trb *event_trb, struct xhci_transfer_event *event,
	struct xhci_virt_ep *ep, int *status)
{
	struct xhci_ring *ep_ring;
	struct urb_priv *urb_priv;
	int idx;
	int len = 0;
	union xhci_trb *cur_trb;
	struct xhci_segment *cur_seg;
	struct usb_iso_packet_descriptor *frame;
	u32 trb_comp_code;
	bool skip_td = false;

	ep_ring = xhci_dma_to_transfer_ring(ep, le64_to_cpu(event->buffer));
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	urb_priv = td->urb->hcpriv;
	idx = urb_priv->td_cnt;
	frame = &td->urb->iso_frame_desc[idx];

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		if (EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)) == 0) {
			frame->status = 0;
			break;
		}
		if ((xhci->quirks & XHCI_TRUST_TX_LENGTH))
			trb_comp_code = COMP_SHORT_TX;
	 
	case COMP_STOP_SHORT:
	case COMP_SHORT_TX:
		frame->status = td->urb->transfer_flags & URB_SHORT_NOT_OK ?
				-EREMOTEIO : 0;
		break;
	case COMP_BW_OVER:
		frame->status = -ECOMM;
		skip_td = true;
		break;
	case COMP_BUFF_OVER:
	case COMP_BABBLE:
		frame->status = -EOVERFLOW;
		skip_td = true;
		break;
	case COMP_DEV_ERR:
	case COMP_STALL:
		frame->status = -EPROTO;
		skip_td = true;
		break;
	case COMP_TX_ERR:
		frame->status = -EPROTO;
		if (event_trb != td->last_trb)
			return 0;
		skip_td = true;
		break;
	case COMP_STOP:
	case COMP_STOP_INVAL:
		break;
	default:
		frame->status = -1;
		break;
	}

	if (trb_comp_code == COMP_SUCCESS || skip_td) {
		frame->actual_length = frame->length;
		td->urb->actual_length += frame->length;
	} else if (trb_comp_code == COMP_STOP_SHORT) {
		frame->actual_length =
			EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
		td->urb->actual_length += frame->actual_length;
	} else {
		for (cur_trb = ep_ring->dequeue,
		     cur_seg = ep_ring->deq_seg; cur_trb != event_trb;
		     next_trb(xhci, ep_ring, &cur_seg, &cur_trb)) {
			if (!TRB_TYPE_NOOP_LE32(cur_trb->generic.field[3]) &&
			    !TRB_TYPE_LINK_LE32(cur_trb->generic.field[3]))
				len += TRB_LEN(le32_to_cpu(cur_trb->generic.field[2]));
		}
		len += TRB_LEN(le32_to_cpu(cur_trb->generic.field[2])) -
			EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));

		if (trb_comp_code != COMP_STOP_INVAL) {
			frame->actual_length = len;
			td->urb->actual_length += len;
		}
	}

	return finish_td(xhci, td, event_trb, event, ep, status, false);
}

static int skip_isoc_td(struct xhci_hcd *xhci, struct xhci_td *td,
			struct xhci_transfer_event *event,
			struct xhci_virt_ep *ep, int *status)
{
	struct xhci_ring *ep_ring;
	struct urb_priv *urb_priv;
	struct usb_iso_packet_descriptor *frame;
	int idx;

	ep_ring = xhci_dma_to_transfer_ring(ep, le64_to_cpu(event->buffer));
	urb_priv = td->urb->hcpriv;
	idx = urb_priv->td_cnt;
	frame = &td->urb->iso_frame_desc[idx];

	frame->status = -EXDEV;

	frame->actual_length = 0;

	while (ep_ring->dequeue != td->last_trb)
		inc_deq(xhci, ep_ring);
	inc_deq(xhci, ep_ring);

	return finish_td(xhci, td, NULL, event, ep, status, true);
}

static int process_bulk_intr_td(struct xhci_hcd *xhci, struct xhci_td *td,
	union xhci_trb *event_trb, struct xhci_transfer_event *event,
	struct xhci_virt_ep *ep, int *status)
{
	struct xhci_ring *ep_ring;
	union xhci_trb *cur_trb;
	struct xhci_segment *cur_seg;
	u32 trb_comp_code;

	ep_ring = xhci_dma_to_transfer_ring(ep, le64_to_cpu(event->buffer));
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));

	switch (trb_comp_code) {
	case COMP_SUCCESS:
		 
		if (event_trb != td->last_trb ||
		    EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)) != 0) {
			xhci_warn(xhci, "WARN Successful completion "
					"on short TX\n");
			if (td->urb->transfer_flags & URB_SHORT_NOT_OK)
				*status = -EREMOTEIO;
			else
				*status = 0;
			if ((xhci->quirks & XHCI_TRUST_TX_LENGTH))
				trb_comp_code = COMP_SHORT_TX;
		} else {
			*status = 0;
		}
		break;
	case COMP_STOP_SHORT:
	case COMP_SHORT_TX:
		if (td->urb->transfer_flags & URB_SHORT_NOT_OK)
			*status = -EREMOTEIO;
		else
			*status = 0;
		break;
	default:
		 
		break;
	}
	if (trb_comp_code == COMP_SHORT_TX)
		xhci_dbg(xhci, "ep %#x - asked for %d bytes, "
				"%d bytes untransferred\n",
				td->urb->ep->desc.bEndpointAddress,
				td->urb->transfer_buffer_length,
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)));
	 
	if (trb_comp_code == COMP_STOP_SHORT) {
		td->urb->actual_length =
			EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));

		if (td->urb->transfer_buffer_length <
				td->urb->actual_length) {
			xhci_warn(xhci, "HC gave bad length of %d bytes txed\n",
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)));
			td->urb->actual_length = 0;
			  
		}
	 
	} else if (event_trb == td->last_trb) {
		if (EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)) != 0) {
			td->urb->actual_length =
				td->urb->transfer_buffer_length -
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
			if (td->urb->transfer_buffer_length <
					td->urb->actual_length) {
				xhci_warn(xhci, "HC gave bad length "
						"of %d bytes left\n",
					  EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)));
				td->urb->actual_length = 0;
				if (td->urb->transfer_flags & URB_SHORT_NOT_OK)
					*status = -EREMOTEIO;
				else
					*status = 0;
			}
			 
			if (*status == -EINPROGRESS) {
				if (td->urb->transfer_flags & URB_SHORT_NOT_OK)
					*status = -EREMOTEIO;
				else
					*status = 0;
			}
		} else {
			td->urb->actual_length =
				td->urb->transfer_buffer_length;
			 
			if (*status == -EREMOTEIO)
				*status = 0;
		}
	} else {
		 
		td->urb->actual_length = 0;
		for (cur_trb = ep_ring->dequeue, cur_seg = ep_ring->deq_seg;
				cur_trb != event_trb;
				next_trb(xhci, ep_ring, &cur_seg, &cur_trb)) {
			if (!TRB_TYPE_NOOP_LE32(cur_trb->generic.field[3]) &&
			    !TRB_TYPE_LINK_LE32(cur_trb->generic.field[3]))
				td->urb->actual_length +=
					TRB_LEN(le32_to_cpu(cur_trb->generic.field[2]));
		}
		 
		if (trb_comp_code != COMP_STOP_INVAL)
			td->urb->actual_length +=
				TRB_LEN(le32_to_cpu(cur_trb->generic.field[2])) -
				EVENT_TRB_LEN(le32_to_cpu(event->transfer_len));
	}

	return finish_td(xhci, td, event_trb, event, ep, status, false);
}

static int handle_tx_event(struct xhci_hcd *xhci,
		struct xhci_transfer_event *event)
	__releases(&xhci->lock)
	__acquires(&xhci->lock)
{
	struct xhci_virt_device *xdev;
	struct xhci_virt_ep *ep;
	struct xhci_ring *ep_ring;
	unsigned int slot_id;
	int ep_index;
	struct xhci_td *td = NULL;
	dma_addr_t event_dma;
	struct xhci_segment *event_seg;
	union xhci_trb *event_trb;
	struct urb *urb = NULL;
	int status = -EINPROGRESS;
	struct urb_priv *urb_priv;
	struct xhci_ep_ctx *ep_ctx;
	struct list_head *tmp;
	u32 trb_comp_code;
	int ret = 0;
	int td_num = 0;
	bool handling_skipped_tds = false;

	slot_id = TRB_TO_SLOT_ID(le32_to_cpu(event->flags));
	xdev = xhci->devs[slot_id];
	if (!xdev) {
		xhci_err(xhci, "ERROR Transfer event pointed to bad slot\n");
		xhci_err(xhci, "@%016llx %08x %08x %08x %08x\n",
			 (unsigned long long) xhci_trb_virt_to_dma(
				 xhci->event_ring->deq_seg,
				 xhci->event_ring->dequeue),
			 lower_32_bits(le64_to_cpu(event->buffer)),
			 upper_32_bits(le64_to_cpu(event->buffer)),
			 le32_to_cpu(event->transfer_len),
			 le32_to_cpu(event->flags));
		xhci_dbg(xhci, "Event ring:\n");
		xhci_debug_segment(xhci, xhci->event_ring->deq_seg);
		return -ENODEV;
	}

	ep_index = TRB_TO_EP_ID(le32_to_cpu(event->flags)) - 1;
	ep = &xdev->eps[ep_index];
	ep_ring = xhci_dma_to_transfer_ring(ep, le64_to_cpu(event->buffer));
	ep_ctx = xhci_get_ep_ctx(xhci, xdev->out_ctx, ep_index);
	if (!ep_ring ||
	    (le32_to_cpu(ep_ctx->ep_info) & EP_STATE_MASK) ==
	    EP_STATE_DISABLED) {
		xhci_err(xhci, "ERROR Transfer event for disabled endpoint "
				"or incorrect stream ring\n");
		xhci_err(xhci, "@%016llx %08x %08x %08x %08x\n",
			 (unsigned long long) xhci_trb_virt_to_dma(
				 xhci->event_ring->deq_seg,
				 xhci->event_ring->dequeue),
			 lower_32_bits(le64_to_cpu(event->buffer)),
			 upper_32_bits(le64_to_cpu(event->buffer)),
			 le32_to_cpu(event->transfer_len),
			 le32_to_cpu(event->flags));
		xhci_dbg(xhci, "Event ring:\n");
		xhci_debug_segment(xhci, xhci->event_ring->deq_seg);
		return -ENODEV;
	}

	if (ep->skip) {
		list_for_each(tmp, &ep_ring->td_list)
			td_num++;
	}

	event_dma = le64_to_cpu(event->buffer);
	trb_comp_code = GET_COMP_CODE(le32_to_cpu(event->transfer_len));
	 
	switch (trb_comp_code) {
	 
	case COMP_SUCCESS:
		if (EVENT_TRB_LEN(le32_to_cpu(event->transfer_len)) == 0)
			break;
		if (xhci->quirks & XHCI_TRUST_TX_LENGTH)
			trb_comp_code = COMP_SHORT_TX;
		else
			xhci_warn_ratelimited(xhci,
					"WARN Successful completion on short TX: needs XHCI_TRUST_TX_LENGTH quirk?\n");
	case COMP_SHORT_TX:
		break;
	case COMP_STOP:
		xhci_dbg(xhci, "Stopped on Transfer TRB\n");
		break;
	case COMP_STOP_INVAL:
		xhci_dbg(xhci, "Stopped on No-op or Link TRB\n");
		break;
	case COMP_STOP_SHORT:
		xhci_dbg(xhci, "Stopped with short packet transfer detected\n");
		break;
	case COMP_STALL:
		xhci_dbg(xhci, "Stalled endpoint\n");
		ep->ep_state |= EP_HALTED;
		status = -EPIPE;
		break;
	case COMP_TRB_ERR:
		xhci_warn(xhci, "WARN: TRB error on endpoint\n");
		status = -EILSEQ;
		break;
	case COMP_SPLIT_ERR:
	case COMP_TX_ERR:
		xhci_dbg(xhci, "Transfer error on endpoint\n");
		status = -EPROTO;
		break;
	case COMP_BABBLE:
		xhci_dbg(xhci, "Babble error on endpoint\n");
		status = -EOVERFLOW;
		break;
	case COMP_DB_ERR:
		xhci_warn(xhci, "WARN: HC couldn't access mem fast enough\n");
		status = -ENOSR;
		break;
	case COMP_BW_OVER:
		xhci_warn(xhci, "WARN: bandwidth overrun event on endpoint\n");
		break;
	case COMP_BUFF_OVER:
		xhci_warn(xhci, "WARN: buffer overrun event on endpoint\n");
		break;
	case COMP_UNDERRUN:
		 
		xhci_dbg(xhci, "underrun event on endpoint\n");
		if (!list_empty(&ep_ring->td_list))
			xhci_dbg(xhci, "Underrun Event for slot %d ep %d "
					"still with TDs queued?\n",
				 TRB_TO_SLOT_ID(le32_to_cpu(event->flags)),
				 ep_index);
		goto cleanup;
	case COMP_OVERRUN:
		xhci_dbg(xhci, "overrun event on endpoint\n");
		if (!list_empty(&ep_ring->td_list))
			xhci_dbg(xhci, "Overrun Event for slot %d ep %d "
					"still with TDs queued?\n",
				 TRB_TO_SLOT_ID(le32_to_cpu(event->flags)),
				 ep_index);
		goto cleanup;
	case COMP_DEV_ERR:
		xhci_warn(xhci, "WARN: detect an incompatible device");
		status = -EPROTO;
		break;
	case COMP_MISSED_INT:
		 
		ep->skip = true;
		xhci_dbg(xhci, "Miss service interval error, set skip flag\n");
		goto cleanup;
	case COMP_PING_ERR:
		ep->skip = true;
		xhci_dbg(xhci, "No Ping response error, Skip one Isoc TD\n");
		goto cleanup;
	default:
		if (xhci_is_vendor_info_code(xhci, trb_comp_code)) {
			status = 0;
			break;
		}
		xhci_warn(xhci, "ERROR Unknown event condition %u, HC probably busted\n",
			  trb_comp_code);
		goto cleanup;
	}

	do {
		 
		if (list_empty(&ep_ring->td_list)) {
			 
			if (!(trb_comp_code == COMP_STOP ||
						trb_comp_code == COMP_STOP_INVAL)) {
				xhci_warn(xhci, "WARN Event TRB for slot %d ep %d with no TDs queued?\n",
						TRB_TO_SLOT_ID(le32_to_cpu(event->flags)),
						ep_index);
				xhci_dbg(xhci, "Event TRB with TRB type ID %u\n",
						(le32_to_cpu(event->flags) &
						 TRB_TYPE_BITMASK)>>10);
				xhci_print_trb_offsets(xhci, (union xhci_trb *) event);
			}
			if (ep->skip) {
				ep->skip = false;
				xhci_dbg(xhci, "td_list is empty while skip "
						"flag set. Clear skip flag.\n");
			}
			ret = 0;
			goto cleanup;
		}

		if (ep->skip && td_num == 0) {
			ep->skip = false;
			xhci_dbg(xhci, "All tds on the ep_ring skipped. "
						"Clear skip flag.\n");
			ret = 0;
			goto cleanup;
		}

		td = list_entry(ep_ring->td_list.next, struct xhci_td, td_list);
		if (ep->skip)
			td_num--;

		event_seg = trb_in_td(xhci, ep_ring->deq_seg, ep_ring->dequeue,
				td->last_trb, event_dma, false);

		if (!event_seg && (trb_comp_code == COMP_STOP ||
				   trb_comp_code == COMP_STOP_INVAL)) {
			ret = 0;
			goto cleanup;
		}

		if (!event_seg) {
			if (!ep->skip ||
			    !usb_endpoint_xfer_isoc(&td->urb->ep->desc)) {
				 
				if ((xhci->quirks & XHCI_SPURIOUS_SUCCESS) &&
						ep_ring->last_td_was_short) {
					ep_ring->last_td_was_short = false;
					ret = 0;
					goto cleanup;
				}
				 
				xhci_err(xhci,
					"ERROR Transfer event TRB DMA ptr not "
					"part of current TD ep_index %d "
					"comp_code %u\n", ep_index,
					trb_comp_code);
				trb_in_td(xhci, ep_ring->deq_seg,
					  ep_ring->dequeue, td->last_trb,
					  event_dma, true);
				return -ESHUTDOWN;
			}

			ret = skip_isoc_td(xhci, td, event, ep, &status);
			goto cleanup;
		}
		if (trb_comp_code == COMP_SHORT_TX)
			ep_ring->last_td_was_short = true;
		else
			ep_ring->last_td_was_short = false;

		if (ep->skip) {
			xhci_dbg(xhci, "Found td. Clear skip flag.\n");
			ep->skip = false;
		}

		event_trb = &event_seg->trbs[(event_dma - event_seg->dma) /
						sizeof(*event_trb)];
		 
		if (TRB_TYPE_NOOP_LE32(event_trb->generic.field[3])) {
			xhci_dbg(xhci,
				 "event_trb is a no-op TRB. Skip it\n");
			goto cleanup;
		}

		if (usb_endpoint_xfer_control(&td->urb->ep->desc))
			ret = process_ctrl_td(xhci, td, event_trb, event, ep,
						 &status);
		else if (usb_endpoint_xfer_isoc(&td->urb->ep->desc))
			ret = process_isoc_td(xhci, td, event_trb, event, ep,
						 &status);
		else
			ret = process_bulk_intr_td(xhci, td, event_trb, event,
						 ep, &status);

cleanup:

		handling_skipped_tds = ep->skip &&
			trb_comp_code != COMP_MISSED_INT &&
			trb_comp_code != COMP_PING_ERR;

		if (!handling_skipped_tds)
			inc_deq(xhci, xhci->event_ring);

		if (ret) {
			urb = td->urb;
			urb_priv = urb->hcpriv;

			xhci_urb_free_priv(urb_priv);

			usb_hcd_unlink_urb_from_ep(bus_to_hcd(urb->dev->bus), urb);
			if ((urb->actual_length != urb->transfer_buffer_length &&
						(urb->transfer_flags &
						 URB_SHORT_NOT_OK)) ||
					(status != 0 &&
					 !usb_endpoint_xfer_isoc(&urb->ep->desc)))
				xhci_dbg(xhci, "Giveback URB %p, len = %d, "
						"expected = %d, status = %d\n",
						urb, urb->actual_length,
						urb->transfer_buffer_length,
						status);
			spin_unlock(&xhci->lock);
			 
			if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS)
				status = 0;
			usb_hcd_giveback_urb(bus_to_hcd(urb->dev->bus), urb, status);
			spin_lock(&xhci->lock);
		}

	} while (handling_skipped_tds);

	return 0;
}

static int xhci_handle_event(struct xhci_hcd *xhci)
{
	union xhci_trb *event;
	int update_ptrs = 1;
	int ret;

	if (!xhci->event_ring || !xhci->event_ring->dequeue) {
		xhci->error_bitmask |= 1 << 1;
		return 0;
	}

	event = xhci->event_ring->dequeue;
	 
	if ((le32_to_cpu(event->event_cmd.flags) & TRB_CYCLE) !=
	    xhci->event_ring->cycle_state) {
		xhci->error_bitmask |= 1 << 2;
		return 0;
	}

	rmb();
	 
	switch ((le32_to_cpu(event->event_cmd.flags) & TRB_TYPE_BITMASK)) {
	case TRB_TYPE(TRB_COMPLETION):
		handle_cmd_completion(xhci, &event->event_cmd);
		break;
	case TRB_TYPE(TRB_PORT_STATUS):
		handle_port_status(xhci, event);
		update_ptrs = 0;
		break;
	case TRB_TYPE(TRB_TRANSFER):
		ret = handle_tx_event(xhci, &event->trans_event);
		if (ret < 0)
			xhci->error_bitmask |= 1 << 9;
		else
			update_ptrs = 0;
		break;
	case TRB_TYPE(TRB_DEV_NOTE):
		handle_device_notification(xhci, event);
		break;
	default:
		if ((le32_to_cpu(event->event_cmd.flags) & TRB_TYPE_BITMASK) >=
		    TRB_TYPE(48))
			handle_vendor_event(xhci, event);
		else
			xhci->error_bitmask |= 1 << 3;
	}
	 
	if (xhci->xhc_state & XHCI_STATE_DYING) {
		xhci_dbg(xhci, "xHCI host dying, returning from "
				"event handler.\n");
		return 0;
	}

	if (update_ptrs)
		 
		inc_deq(xhci, xhci->event_ring);

	return 1;
}

irqreturn_t xhci_irq(struct usb_hcd *hcd)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	u32 status;
	u64 temp_64;
	union xhci_trb *event_ring_deq;
	dma_addr_t deq;

	spin_lock(&xhci->lock);
	 
	status = readl(&xhci->op_regs->status);
	if (status == 0xffffffff)
		goto hw_died;

	if (!(status & STS_EINT)) {
		spin_unlock(&xhci->lock);
		return IRQ_NONE;
	}
	if (status & STS_FATAL) {
		xhci_warn(xhci, "WARNING: Host System Error\n");
		xhci_halt(xhci);
hw_died:
		spin_unlock(&xhci->lock);
		return IRQ_HANDLED;
	}

	status |= STS_EINT;
	writel(status, &xhci->op_regs->status);
	 
	if (hcd->irq) {
		u32 irq_pending;
		 
		irq_pending = readl(&xhci->ir_set->irq_pending);
		irq_pending |= IMAN_IP;
		writel(irq_pending, &xhci->ir_set->irq_pending);
	}

	if (xhci->xhc_state & XHCI_STATE_DYING ||
	    xhci->xhc_state & XHCI_STATE_HALTED) {
		xhci_dbg(xhci, "xHCI dying, ignoring interrupt. "
				"Shouldn't IRQs be disabled?\n");
		 
		temp_64 = xhci_read_64(xhci, &xhci->ir_set->erst_dequeue);
		xhci_write_64(xhci, temp_64 | ERST_EHB,
				&xhci->ir_set->erst_dequeue);
		spin_unlock(&xhci->lock);

		return IRQ_HANDLED;
	}

	event_ring_deq = xhci->event_ring->dequeue;
	 
	while (xhci_handle_event(xhci) > 0) {}

	temp_64 = xhci_read_64(xhci, &xhci->ir_set->erst_dequeue);
	 
	if (event_ring_deq != xhci->event_ring->dequeue) {
		deq = xhci_trb_virt_to_dma(xhci->event_ring->deq_seg,
				xhci->event_ring->dequeue);
		if (deq == 0)
			xhci_warn(xhci, "WARN something wrong with SW event "
					"ring dequeue ptr.\n");
		 
		temp_64 &= ERST_PTR_MASK;
		temp_64 |= ((u64) deq & (u64) ~ERST_PTR_MASK);
	}

	temp_64 |= ERST_EHB;
	xhci_write_64(xhci, temp_64, &xhci->ir_set->erst_dequeue);

	spin_unlock(&xhci->lock);

	return IRQ_HANDLED;
}

irqreturn_t xhci_msi_irq(int irq, void *hcd)
{
	return xhci_irq(hcd);
}

static void queue_trb(struct xhci_hcd *xhci, struct xhci_ring *ring,
		bool more_trbs_coming,
		u32 field1, u32 field2, u32 field3, u32 field4)
{
	struct xhci_generic_trb *trb;

	trb = &ring->enqueue->generic;
	trb->field[0] = cpu_to_le32(field1);
	trb->field[1] = cpu_to_le32(field2);
	trb->field[2] = cpu_to_le32(field3);
	trb->field[3] = cpu_to_le32(field4);
	inc_enq(xhci, ring, more_trbs_coming);
}

static int prepare_ring(struct xhci_hcd *xhci, struct xhci_ring *ep_ring,
		u32 ep_state, unsigned int num_trbs, gfp_t mem_flags)
{
	unsigned int num_trbs_needed;

	switch (ep_state) {
	case EP_STATE_DISABLED:
		 
		xhci_warn(xhci, "WARN urb submitted to disabled ep\n");
		return -ENOENT;
	case EP_STATE_ERROR:
		xhci_warn(xhci, "WARN waiting for error on ep to be cleared\n");
		 
		return -EINVAL;
	case EP_STATE_HALTED:
		xhci_dbg(xhci, "WARN halted endpoint, queueing URB anyway.\n");
	case EP_STATE_STOPPED:
	case EP_STATE_RUNNING:
		break;
	default:
		xhci_err(xhci, "ERROR unknown endpoint state for ep\n");
		 
		return -EINVAL;
	}

	while (1) {
		if (room_on_ring(xhci, ep_ring, num_trbs))
			break;

		if (ep_ring == xhci->cmd_ring) {
			xhci_err(xhci, "Do not support expand command ring\n");
			return -ENOMEM;
		}

		xhci_dbg_trace(xhci, trace_xhci_dbg_ring_expansion,
				"ERROR no room on ep ring, try ring expansion");
		num_trbs_needed = num_trbs - ep_ring->num_trbs_free;
		if (xhci_ring_expansion(xhci, ep_ring, num_trbs_needed,
					mem_flags)) {
			xhci_err(xhci, "Ring expansion failed\n");
			return -ENOMEM;
		}
	}

	if (enqueue_is_link_trb(ep_ring)) {
		struct xhci_ring *ring = ep_ring;
		union xhci_trb *next;

		next = ring->enqueue;

		while (last_trb(xhci, ring, ring->enq_seg, next)) {
			 
			if (!xhci_link_trb_quirk(xhci) &&
					!(ring->type == TYPE_ISOC &&
					 (xhci->quirks & XHCI_AMD_0x96_HOST)))
				next->link.control &= cpu_to_le32(~TRB_CHAIN);
			else
				next->link.control |= cpu_to_le32(TRB_CHAIN);

			wmb();
			next->link.control ^= cpu_to_le32(TRB_CYCLE);

			if (last_trb_on_last_seg(xhci, ring, ring->enq_seg, next)) {
				ring->cycle_state ^= 1;
			}
			ring->enq_seg = ring->enq_seg->next;
			ring->enqueue = ring->enq_seg->trbs;
			next = ring->enqueue;
		}
	}

	return 0;
}

static int prepare_transfer(struct xhci_hcd *xhci,
		struct xhci_virt_device *xdev,
		unsigned int ep_index,
		unsigned int stream_id,
		unsigned int num_trbs,
		struct urb *urb,
		unsigned int td_index,
		gfp_t mem_flags)
{
	int ret;
	struct urb_priv *urb_priv;
	struct xhci_td	*td;
	struct xhci_ring *ep_ring;
	struct xhci_ep_ctx *ep_ctx = xhci_get_ep_ctx(xhci, xdev->out_ctx, ep_index);

	ep_ring = xhci_stream_id_to_ring(xdev, ep_index, stream_id);
	if (!ep_ring) {
		xhci_dbg(xhci, "Can't prepare ring for bad stream ID %u\n",
				stream_id);
		return -EINVAL;
	}

	ret = prepare_ring(xhci, ep_ring,
			   le32_to_cpu(ep_ctx->ep_info) & EP_STATE_MASK,
			   num_trbs, mem_flags);
	if (ret)
		return ret;

	urb_priv = urb->hcpriv;
	td = urb_priv->td[td_index];

	INIT_LIST_HEAD(&td->td_list);
	INIT_LIST_HEAD(&td->cancelled_td_list);

	if (td_index == 0) {
		ret = usb_hcd_link_urb_to_ep(bus_to_hcd(urb->dev->bus), urb);
		if (unlikely(ret))
			return ret;
	}

	td->urb = urb;
	 
	list_add_tail(&td->td_list, &ep_ring->td_list);
	td->start_seg = ep_ring->enq_seg;
	td->first_trb = ep_ring->enqueue;

	urb_priv->td[td_index] = td;

	return 0;
}

static unsigned int count_sg_trbs_needed(struct xhci_hcd *xhci, struct urb *urb)
{
	int num_sgs, num_trbs, running_total, temp, i;
	struct scatterlist *sg;

	sg = NULL;
	num_sgs = urb->num_mapped_sgs;
	temp = urb->transfer_buffer_length;

	num_trbs = 0;
	for_each_sg(urb->sg, sg, num_sgs, i) {
		unsigned int len = sg_dma_len(sg);

		running_total = TRB_MAX_BUFF_SIZE -
			(sg_dma_address(sg) & (TRB_MAX_BUFF_SIZE - 1));
		running_total &= TRB_MAX_BUFF_SIZE - 1;
		if (running_total != 0)
			num_trbs++;

		while (running_total < sg_dma_len(sg) && running_total < temp) {
			num_trbs++;
			running_total += TRB_MAX_BUFF_SIZE;
		}
		len = min_t(int, len, temp);
		temp -= len;
		if (temp == 0)
			break;
	}
	return num_trbs;
}

static void check_trb_math(struct urb *urb, int num_trbs, int running_total)
{
	if (num_trbs != 0)
		dev_err(&urb->dev->dev, "%s - ep %#x - Miscalculated number of "
				"TRBs, %d left\n", __func__,
				urb->ep->desc.bEndpointAddress, num_trbs);
	if (running_total != urb->transfer_buffer_length)
		dev_err(&urb->dev->dev, "%s - ep %#x - Miscalculated tx length, "
				"queued %#x (%d), asked for %#x (%d)\n",
				__func__,
				urb->ep->desc.bEndpointAddress,
				running_total, running_total,
				urb->transfer_buffer_length,
				urb->transfer_buffer_length);
}

static void giveback_first_trb(struct xhci_hcd *xhci, int slot_id,
		unsigned int ep_index, unsigned int stream_id, int start_cycle,
		struct xhci_generic_trb *start_trb)
{
	 
	wmb();
	if (start_cycle)
		start_trb->field[3] |= cpu_to_le32(start_cycle);
	else
		start_trb->field[3] &= cpu_to_le32(~TRB_CYCLE);
	xhci_ring_ep_doorbell(xhci, slot_id, ep_index, stream_id);
}

int xhci_queue_intr_tx(struct xhci_hcd *xhci, gfp_t mem_flags,
		struct urb *urb, int slot_id, unsigned int ep_index)
{
	struct xhci_ep_ctx *ep_ctx = xhci_get_ep_ctx(xhci,
			xhci->devs[slot_id]->out_ctx, ep_index);
	int xhci_interval;
	int ep_interval;

	xhci_interval = EP_INTERVAL_TO_UFRAMES(le32_to_cpu(ep_ctx->ep_info));
	ep_interval = urb->interval;
	 
	if (urb->dev->speed == USB_SPEED_LOW ||
			urb->dev->speed == USB_SPEED_FULL)
		ep_interval *= 8;
	 
	if (xhci_interval != ep_interval) {
		dev_dbg_ratelimited(&urb->dev->dev,
				"Driver uses different interval (%d microframe%s) than xHCI (%d microframe%s)\n",
				ep_interval, ep_interval == 1 ? "" : "s",
				xhci_interval, xhci_interval == 1 ? "" : "s");
		urb->interval = xhci_interval;
		 
		if (urb->dev->speed == USB_SPEED_LOW ||
				urb->dev->speed == USB_SPEED_FULL)
			urb->interval /= 8;
	}
	return xhci_queue_bulk_tx(xhci, mem_flags, urb, slot_id, ep_index);
}

static u32 xhci_td_remainder(struct xhci_hcd *xhci, int transferred,
			      int trb_buff_len, unsigned int td_total_len,
			      struct urb *urb, unsigned int num_trbs_left)
{
	u32 maxp, total_packet_count;

	if (xhci->hci_version < 0x100)
		return ((td_total_len - transferred) >> 10);

	maxp = GET_MAX_PACKET(usb_endpoint_maxp(&urb->ep->desc));
	total_packet_count = DIV_ROUND_UP(td_total_len, maxp);

	if (num_trbs_left == 0 || (transferred == 0 && trb_buff_len == 0) ||
	    trb_buff_len == td_total_len)
		return 0;

	return (total_packet_count - ((transferred + trb_buff_len) / maxp));
}

static int queue_bulk_sg_tx(struct xhci_hcd *xhci, gfp_t mem_flags,
		struct urb *urb, int slot_id, unsigned int ep_index)
{
	struct xhci_ring *ep_ring;
	unsigned int num_trbs;
	struct urb_priv *urb_priv;
	struct xhci_td *td;
	struct scatterlist *sg;
	int num_sgs;
	int trb_buff_len, this_sg_len, running_total, ret;
	unsigned int total_packet_count;
	bool zero_length_needed;
	bool first_trb;
	int last_trb_num;
	u64 addr;
	bool more_trbs_coming;

	struct xhci_generic_trb *start_trb;
	int start_cycle;

	ep_ring = xhci_urb_to_transfer_ring(xhci, urb);
	if (!ep_ring)
		return -EINVAL;

	num_trbs = count_sg_trbs_needed(xhci, urb);
	num_sgs = urb->num_mapped_sgs;
	total_packet_count = DIV_ROUND_UP(urb->transfer_buffer_length,
			usb_endpoint_maxp(&urb->ep->desc));

	ret = prepare_transfer(xhci, xhci->devs[slot_id],
			ep_index, urb->stream_id,
			num_trbs, urb, 0, mem_flags);
	if (ret < 0)
		return ret;

	urb_priv = urb->hcpriv;

	zero_length_needed = urb->transfer_flags & URB_ZERO_PACKET &&
		urb_priv->length == 2;
	if (zero_length_needed) {
		num_trbs++;
		xhci_dbg(xhci, "Creating zero length td.\n");
		ret = prepare_transfer(xhci, xhci->devs[slot_id],
				ep_index, urb->stream_id,
				1, urb, 1, mem_flags);
		if (ret < 0)
			return ret;
	}

	td = urb_priv->td[0];

	start_trb = &ep_ring->enqueue->generic;
	start_cycle = ep_ring->cycle_state;

	running_total = 0;
	 
	sg = urb->sg;
	addr = (u64) sg_dma_address(sg);
	this_sg_len = sg_dma_len(sg);
	trb_buff_len = TRB_MAX_BUFF_SIZE - (addr & (TRB_MAX_BUFF_SIZE - 1));
	trb_buff_len = min_t(int, trb_buff_len, this_sg_len);
	if (trb_buff_len > urb->transfer_buffer_length)
		trb_buff_len = urb->transfer_buffer_length;

	first_trb = true;
	last_trb_num = zero_length_needed ? 2 : 1;
	 
	do {
		u32 field = 0;
		u32 length_field = 0;
		u32 remainder = 0;

		if (first_trb) {
			first_trb = false;
			if (start_cycle == 0)
				field |= 0x1;
		} else
			field |= ep_ring->cycle_state;

		if (num_trbs > last_trb_num) {
			field |= TRB_CHAIN;
		} else if (num_trbs == last_trb_num) {
			td->last_trb = ep_ring->enqueue;
			field |= TRB_IOC;
		} else if (zero_length_needed && num_trbs == 1) {
			trb_buff_len = 0;
			urb_priv->td[1]->last_trb = ep_ring->enqueue;
			field |= TRB_IOC;
		}

		if (usb_urb_dir_in(urb))
			field |= TRB_ISP;

		if (TRB_MAX_BUFF_SIZE -
				(addr & (TRB_MAX_BUFF_SIZE - 1)) < trb_buff_len) {
			xhci_warn(xhci, "WARN: sg dma xfer crosses 64KB boundaries!\n");
			xhci_dbg(xhci, "Next boundary at %#x, end dma = %#x\n",
					(unsigned int) (addr + TRB_MAX_BUFF_SIZE) & ~(TRB_MAX_BUFF_SIZE - 1),
					(unsigned int) addr + trb_buff_len);
		}

		remainder = xhci_td_remainder(xhci, running_total, trb_buff_len,
					   urb->transfer_buffer_length,
					   urb, num_trbs - 1);

		length_field = TRB_LEN(trb_buff_len) |
			TRB_TD_SIZE(remainder) |
			TRB_INTR_TARGET(0);

		if (num_trbs > 1)
			more_trbs_coming = true;
		else
			more_trbs_coming = false;
		queue_trb(xhci, ep_ring, more_trbs_coming,
				lower_32_bits(addr),
				upper_32_bits(addr),
				length_field,
				field | TRB_TYPE(TRB_NORMAL));
		--num_trbs;
		running_total += trb_buff_len;

		this_sg_len -= trb_buff_len;
		if (this_sg_len == 0) {
			--num_sgs;
			if (num_sgs == 0)
				break;
			sg = sg_next(sg);
			addr = (u64) sg_dma_address(sg);
			this_sg_len = sg_dma_len(sg);
		} else {
			addr += trb_buff_len;
		}

		trb_buff_len = TRB_MAX_BUFF_SIZE -
			(addr & (TRB_MAX_BUFF_SIZE - 1));
		trb_buff_len = min_t(int, trb_buff_len, this_sg_len);
		if (running_total + trb_buff_len > urb->transfer_buffer_length)
			trb_buff_len =
				urb->transfer_buffer_length - running_total;
	} while (num_trbs > 0);

	check_trb_math(urb, num_trbs, running_total);
	giveback_first_trb(xhci, slot_id, ep_index, urb->stream_id,
			start_cycle, start_trb);
	return 0;
}

int xhci_queue_bulk_tx(struct xhci_hcd *xhci, gfp_t mem_flags,
		struct urb *urb, int slot_id, unsigned int ep_index)
{
	struct xhci_ring *ep_ring;
	struct urb_priv *urb_priv;
	struct xhci_td *td;
	int num_trbs;
	struct xhci_generic_trb *start_trb;
	bool first_trb;
	int last_trb_num;
	bool more_trbs_coming;
	bool zero_length_needed;
	int start_cycle;
	u32 field, length_field;

	int running_total, trb_buff_len, ret;
	unsigned int total_packet_count;
	u64 addr;

	if (urb->num_sgs)
		return queue_bulk_sg_tx(xhci, mem_flags, urb, slot_id, ep_index);

	ep_ring = xhci_urb_to_transfer_ring(xhci, urb);
	if (!ep_ring)
		return -EINVAL;

	num_trbs = 0;
	 
	running_total = TRB_MAX_BUFF_SIZE -
		(urb->transfer_dma & (TRB_MAX_BUFF_SIZE - 1));
	running_total &= TRB_MAX_BUFF_SIZE - 1;

	if (running_total != 0 || urb->transfer_buffer_length == 0)
		num_trbs++;
	 
	while (running_total < urb->transfer_buffer_length) {
		num_trbs++;
		running_total += TRB_MAX_BUFF_SIZE;
	}

	ret = prepare_transfer(xhci, xhci->devs[slot_id],
			ep_index, urb->stream_id,
			num_trbs, urb, 0, mem_flags);
	if (ret < 0)
		return ret;

	urb_priv = urb->hcpriv;

	zero_length_needed = urb->transfer_flags & URB_ZERO_PACKET &&
		urb_priv->length == 2;
	if (zero_length_needed) {
		num_trbs++;
		xhci_dbg(xhci, "Creating zero length td.\n");
		ret = prepare_transfer(xhci, xhci->devs[slot_id],
				ep_index, urb->stream_id,
				1, urb, 1, mem_flags);
		if (ret < 0)
			return ret;
	}

	td = urb_priv->td[0];

	start_trb = &ep_ring->enqueue->generic;
	start_cycle = ep_ring->cycle_state;

	running_total = 0;
	total_packet_count = DIV_ROUND_UP(urb->transfer_buffer_length,
			usb_endpoint_maxp(&urb->ep->desc));
	 
	addr = (u64) urb->transfer_dma;
	trb_buff_len = TRB_MAX_BUFF_SIZE -
		(urb->transfer_dma & (TRB_MAX_BUFF_SIZE - 1));
	if (trb_buff_len > urb->transfer_buffer_length)
		trb_buff_len = urb->transfer_buffer_length;

	first_trb = true;
	last_trb_num = zero_length_needed ? 2 : 1;
	 
	do {
		u32 remainder = 0;
		field = 0;

		if (first_trb) {
			first_trb = false;
			if (start_cycle == 0)
				field |= 0x1;
		} else
			field |= ep_ring->cycle_state;

		if (num_trbs > last_trb_num) {
			field |= TRB_CHAIN;
		} else if (num_trbs == last_trb_num) {
			td->last_trb = ep_ring->enqueue;
			field |= TRB_IOC;
		} else if (zero_length_needed && num_trbs == 1) {
			trb_buff_len = 0;
			urb_priv->td[1]->last_trb = ep_ring->enqueue;
			field |= TRB_IOC;
		}

		if (usb_urb_dir_in(urb))
			field |= TRB_ISP;

		remainder = xhci_td_remainder(xhci, running_total, trb_buff_len,
					   urb->transfer_buffer_length,
					   urb, num_trbs - 1);

		length_field = TRB_LEN(trb_buff_len) |
			TRB_TD_SIZE(remainder) |
			TRB_INTR_TARGET(0);

		if (num_trbs > 1)
			more_trbs_coming = true;
		else
			more_trbs_coming = false;
		queue_trb(xhci, ep_ring, more_trbs_coming,
				lower_32_bits(addr),
				upper_32_bits(addr),
				length_field,
				field | TRB_TYPE(TRB_NORMAL));
		--num_trbs;
		running_total += trb_buff_len;

		addr += trb_buff_len;
		trb_buff_len = urb->transfer_buffer_length - running_total;
		if (trb_buff_len > TRB_MAX_BUFF_SIZE)
			trb_buff_len = TRB_MAX_BUFF_SIZE;
	} while (num_trbs > 0);

	check_trb_math(urb, num_trbs, running_total);
	giveback_first_trb(xhci, slot_id, ep_index, urb->stream_id,
			start_cycle, start_trb);
	return 0;
}

int xhci_queue_ctrl_tx(struct xhci_hcd *xhci, gfp_t mem_flags,
		struct urb *urb, int slot_id, unsigned int ep_index)
{
	struct xhci_ring *ep_ring;
	int num_trbs;
	int ret;
	struct usb_ctrlrequest *setup;
	struct xhci_generic_trb *start_trb;
	int start_cycle;
	u32 field, length_field, remainder;
	struct urb_priv *urb_priv;
	struct xhci_td *td;

	ep_ring = xhci_urb_to_transfer_ring(xhci, urb);
	if (!ep_ring)
		return -EINVAL;

	if (!urb->setup_packet)
		return -EINVAL;

	num_trbs = 2;
	 
	if (urb->transfer_buffer_length > 0)
		num_trbs++;
	ret = prepare_transfer(xhci, xhci->devs[slot_id],
			ep_index, urb->stream_id,
			num_trbs, urb, 0, mem_flags);
	if (ret < 0)
		return ret;

	urb_priv = urb->hcpriv;
	td = urb_priv->td[0];

	start_trb = &ep_ring->enqueue->generic;
	start_cycle = ep_ring->cycle_state;

	setup = (struct usb_ctrlrequest *) urb->setup_packet;
	field = 0;
	field |= TRB_IDT | TRB_TYPE(TRB_SETUP);
	if (start_cycle == 0)
		field |= 0x1;

	if (xhci->hci_version >= 0x100) {
		if (urb->transfer_buffer_length > 0) {
			if (setup->bRequestType & USB_DIR_IN)
				field |= TRB_TX_TYPE(TRB_DATA_IN);
			else
				field |= TRB_TX_TYPE(TRB_DATA_OUT);
		}
	}

	queue_trb(xhci, ep_ring, true,
		  setup->bRequestType | setup->bRequest << 8 | le16_to_cpu(setup->wValue) << 16,
		  le16_to_cpu(setup->wIndex) | le16_to_cpu(setup->wLength) << 16,
		  TRB_LEN(8) | TRB_INTR_TARGET(0),
		   
		  field);

	if (usb_urb_dir_in(urb))
		field = TRB_ISP | TRB_TYPE(TRB_DATA);
	else
		field = TRB_TYPE(TRB_DATA);

	remainder = xhci_td_remainder(xhci, 0,
				   urb->transfer_buffer_length,
				   urb->transfer_buffer_length,
				   urb, 1);

	length_field = TRB_LEN(urb->transfer_buffer_length) |
		TRB_TD_SIZE(remainder) |
		TRB_INTR_TARGET(0);

	if (urb->transfer_buffer_length > 0) {
		if (setup->bRequestType & USB_DIR_IN)
			field |= TRB_DIR_IN;
		queue_trb(xhci, ep_ring, true,
				lower_32_bits(urb->transfer_dma),
				upper_32_bits(urb->transfer_dma),
				length_field,
				field | ep_ring->cycle_state);
	}

	td->last_trb = ep_ring->enqueue;

	if (urb->transfer_buffer_length > 0 && setup->bRequestType & USB_DIR_IN)
		field = 0;
	else
		field = TRB_DIR_IN;
	queue_trb(xhci, ep_ring, false,
			0,
			0,
			TRB_INTR_TARGET(0),
			 
			field | TRB_IOC | TRB_TYPE(TRB_STATUS) | ep_ring->cycle_state);

	giveback_first_trb(xhci, slot_id, ep_index, 0,
			start_cycle, start_trb);
	return 0;
}

static int count_isoc_trbs_needed(struct xhci_hcd *xhci,
		struct urb *urb, int i)
{
	int num_trbs = 0;
	u64 addr, td_len;

	addr = (u64) (urb->transfer_dma + urb->iso_frame_desc[i].offset);
	td_len = urb->iso_frame_desc[i].length;

	num_trbs = DIV_ROUND_UP(td_len + (addr & (TRB_MAX_BUFF_SIZE - 1)),
			TRB_MAX_BUFF_SIZE);
	if (num_trbs == 0)
		num_trbs++;

	return num_trbs;
}

static unsigned int xhci_get_burst_count(struct xhci_hcd *xhci,
		struct usb_device *udev,
		struct urb *urb, unsigned int total_packet_count)
{
	unsigned int max_burst;

	if (xhci->hci_version < 0x100 || udev->speed < USB_SPEED_SUPER)
		return 0;

	max_burst = urb->ep->ss_ep_comp.bMaxBurst;
	return DIV_ROUND_UP(total_packet_count, max_burst + 1) - 1;
}

static unsigned int xhci_get_last_burst_packet_count(struct xhci_hcd *xhci,
		struct usb_device *udev,
		struct urb *urb, unsigned int total_packet_count)
{
	unsigned int max_burst;
	unsigned int residue;

	if (xhci->hci_version < 0x100)
		return 0;

	switch (udev->speed) {
	case USB_SPEED_SUPER_PLUS:
	case USB_SPEED_SUPER:
		 
		max_burst = urb->ep->ss_ep_comp.bMaxBurst;
		residue = total_packet_count % (max_burst + 1);
		 
		if (residue == 0)
			return max_burst;
		return residue - 1;
	default:
		if (total_packet_count == 0)
			return 0;
		return total_packet_count - 1;
	}
}

static int xhci_get_isoc_frame_id(struct xhci_hcd *xhci,
		struct urb *urb, int index)
{
	int start_frame, ist, ret = 0;
	int start_frame_id, end_frame_id, current_frame_id;

	if (urb->dev->speed == USB_SPEED_LOW ||
			urb->dev->speed == USB_SPEED_FULL)
		start_frame = urb->start_frame + index * urb->interval;
	else
		start_frame = (urb->start_frame + index * urb->interval) >> 3;

	ist = HCS_IST(xhci->hcs_params2) & 0x7;
	if (HCS_IST(xhci->hcs_params2) & (1 << 3))
		ist <<= 3;

	current_frame_id = readl(&xhci->run_regs->microframe_index);
	start_frame_id = roundup(current_frame_id + ist + 1, 8);
	end_frame_id = rounddown(current_frame_id + 895 * 8, 8);

	start_frame &= 0x7ff;
	start_frame_id = (start_frame_id >> 3) & 0x7ff;
	end_frame_id = (end_frame_id >> 3) & 0x7ff;

	xhci_dbg(xhci, "%s: index %d, reg 0x%x start_frame_id 0x%x, end_frame_id 0x%x, start_frame 0x%x\n",
		 __func__, index, readl(&xhci->run_regs->microframe_index),
		 start_frame_id, end_frame_id, start_frame);

	if (start_frame_id < end_frame_id) {
		if (start_frame > end_frame_id ||
				start_frame < start_frame_id)
			ret = -EINVAL;
	} else if (start_frame_id > end_frame_id) {
		if ((start_frame > end_frame_id &&
				start_frame < start_frame_id))
			ret = -EINVAL;
	} else {
			ret = -EINVAL;
	}

	if (index == 0) {
		if (ret == -EINVAL || start_frame == start_frame_id) {
			start_frame = start_frame_id + 1;
			if (urb->dev->speed == USB_SPEED_LOW ||
					urb->dev->speed == USB_SPEED_FULL)
				urb->start_frame = start_frame;
			else
				urb->start_frame = start_frame << 3;
			ret = 0;
		}
	}

	if (ret) {
		xhci_warn(xhci, "Frame ID %d (reg %d, index %d) beyond range (%d, %d)\n",
				start_frame, current_frame_id, index,
				start_frame_id, end_frame_id);
		xhci_warn(xhci, "Ignore frame ID field, use SIA bit instead\n");
		return ret;
	}

	return start_frame;
}

static int xhci_queue_isoc_tx(struct xhci_hcd *xhci, gfp_t mem_flags,
		struct urb *urb, int slot_id, unsigned int ep_index)
{
	struct xhci_ring *ep_ring;
	struct urb_priv *urb_priv;
	struct xhci_td *td;
	int num_tds, trbs_per_td;
	struct xhci_generic_trb *start_trb;
	bool first_trb;
	int start_cycle;
	u32 field, length_field;
	int running_total, trb_buff_len, td_len, td_remain_len, ret;
	u64 start_addr, addr;
	int i, j;
	bool more_trbs_coming;
	struct xhci_virt_ep *xep;

	xep = &xhci->devs[slot_id]->eps[ep_index];
	ep_ring = xhci->devs[slot_id]->eps[ep_index].ring;

	num_tds = urb->number_of_packets;
	if (num_tds < 1) {
		xhci_dbg(xhci, "Isoc URB with zero packets?\n");
		return -EINVAL;
	}

	start_addr = (u64) urb->transfer_dma;
	start_trb = &ep_ring->enqueue->generic;
	start_cycle = ep_ring->cycle_state;

	urb_priv = urb->hcpriv;
	 
	for (i = 0; i < num_tds; i++) {
		unsigned int total_packet_count;
		unsigned int burst_count;
		unsigned int residue;

		first_trb = true;
		running_total = 0;
		addr = start_addr + urb->iso_frame_desc[i].offset;
		td_len = urb->iso_frame_desc[i].length;
		td_remain_len = td_len;
		total_packet_count = DIV_ROUND_UP(td_len,
				GET_MAX_PACKET(
					usb_endpoint_maxp(&urb->ep->desc)));
		 
		if (total_packet_count == 0)
			total_packet_count++;
		burst_count = xhci_get_burst_count(xhci, urb->dev, urb,
				total_packet_count);
		residue = xhci_get_last_burst_packet_count(xhci,
				urb->dev, urb, total_packet_count);

		trbs_per_td = count_isoc_trbs_needed(xhci, urb, i);

		ret = prepare_transfer(xhci, xhci->devs[slot_id], ep_index,
				urb->stream_id, trbs_per_td, urb, i, mem_flags);
		if (ret < 0) {
			if (i == 0)
				return ret;
			goto cleanup;
		}

		td = urb_priv->td[i];
		for (j = 0; j < trbs_per_td; j++) {
			int frame_id = 0;
			u32 remainder = 0;
			field = 0;

			if (first_trb) {
				field = TRB_TBC(burst_count) |
					TRB_TLBPC(residue);
				 
				field |= TRB_TYPE(TRB_ISOC);

				if (!(urb->transfer_flags & URB_ISO_ASAP) &&
						HCC_CFC(xhci->hcc_params)) {
					frame_id = xhci_get_isoc_frame_id(xhci,
									  urb,
									  i);
					if (frame_id >= 0)
						field |= TRB_FRAME_ID(frame_id);
					else
						field |= TRB_SIA;
				} else
					field |= TRB_SIA;

				if (i == 0) {
					if (start_cycle == 0)
						field |= 0x1;
				} else
					field |= ep_ring->cycle_state;
				first_trb = false;
			} else {
				 
				field |= TRB_TYPE(TRB_NORMAL);
				field |= ep_ring->cycle_state;
			}

			if (usb_urb_dir_in(urb))
				field |= TRB_ISP;

			if (j < trbs_per_td - 1) {
				field |= TRB_CHAIN;
				more_trbs_coming = true;
			} else {
				td->last_trb = ep_ring->enqueue;
				field |= TRB_IOC;
				if (xhci->hci_version == 0x100 &&
						!(xhci->quirks &
							XHCI_AVOID_BEI)) {
					 
					if (i < num_tds - 1)
						field |= TRB_BEI;
				}
				more_trbs_coming = false;
			}

			trb_buff_len = TRB_MAX_BUFF_SIZE -
				(addr & ((1 << TRB_MAX_BUFF_SHIFT) - 1));
			if (trb_buff_len > td_remain_len)
				trb_buff_len = td_remain_len;

			remainder = xhci_td_remainder(xhci, running_total,
						   trb_buff_len, td_len,
						   urb, trbs_per_td - j - 1);

			length_field = TRB_LEN(trb_buff_len) |
				TRB_TD_SIZE(remainder) |
				TRB_INTR_TARGET(0);

			queue_trb(xhci, ep_ring, more_trbs_coming,
				lower_32_bits(addr),
				upper_32_bits(addr),
				length_field,
				field);
			running_total += trb_buff_len;

			addr += trb_buff_len;
			td_remain_len -= trb_buff_len;
		}

		if (running_total != td_len) {
			xhci_err(xhci, "ISOC TD length unmatch\n");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	if (HCC_CFC(xhci->hcc_params))
		xep->next_frame_id = urb->start_frame + num_tds * urb->interval;

	if (xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs == 0) {
		if (xhci->quirks & XHCI_AMD_PLL_FIX)
			usb_amd_quirk_pll_disable();
	}
	xhci_to_hcd(xhci)->self.bandwidth_isoc_reqs++;

	giveback_first_trb(xhci, slot_id, ep_index, urb->stream_id,
			start_cycle, start_trb);
	return 0;
cleanup:
	 
	for (i--; i >= 0; i--)
		list_del_init(&urb_priv->td[i]->td_list);

	urb_priv->td[0]->last_trb = ep_ring->enqueue;
	 
	td_to_noop(xhci, ep_ring, urb_priv->td[0], true);

	ep_ring->enqueue = urb_priv->td[0]->first_trb;
	ep_ring->enq_seg = urb_priv->td[0]->start_seg;
	ep_ring->cycle_state = start_cycle;
	ep_ring->num_trbs_free = ep_ring->num_trbs_free_temp;
	usb_hcd_unlink_urb_from_ep(bus_to_hcd(urb->dev->bus), urb);
	return ret;
}

int xhci_queue_isoc_tx_prepare(struct xhci_hcd *xhci, gfp_t mem_flags,
		struct urb *urb, int slot_id, unsigned int ep_index)
{
	struct xhci_virt_device *xdev;
	struct xhci_ring *ep_ring;
	struct xhci_ep_ctx *ep_ctx;
	int start_frame;
	int xhci_interval;
	int ep_interval;
	int num_tds, num_trbs, i;
	int ret;
	struct xhci_virt_ep *xep;
	int ist;

	xdev = xhci->devs[slot_id];
	xep = &xhci->devs[slot_id]->eps[ep_index];
	ep_ring = xdev->eps[ep_index].ring;
	ep_ctx = xhci_get_ep_ctx(xhci, xdev->out_ctx, ep_index);

	num_trbs = 0;
	num_tds = urb->number_of_packets;
	for (i = 0; i < num_tds; i++)
		num_trbs += count_isoc_trbs_needed(xhci, urb, i);

	ret = prepare_ring(xhci, ep_ring, le32_to_cpu(ep_ctx->ep_info) & EP_STATE_MASK,
			   num_trbs, mem_flags);
	if (ret)
		return ret;

	xhci_interval = EP_INTERVAL_TO_UFRAMES(le32_to_cpu(ep_ctx->ep_info));
	ep_interval = urb->interval;
	 
	if (urb->dev->speed == USB_SPEED_LOW ||
			urb->dev->speed == USB_SPEED_FULL)
		ep_interval *= 8;
	 
	if (xhci_interval != ep_interval) {
		dev_dbg_ratelimited(&urb->dev->dev,
				"Driver uses different interval (%d microframe%s) than xHCI (%d microframe%s)\n",
				ep_interval, ep_interval == 1 ? "" : "s",
				xhci_interval, xhci_interval == 1 ? "" : "s");
		urb->interval = xhci_interval;
		 
		if (urb->dev->speed == USB_SPEED_LOW ||
				urb->dev->speed == USB_SPEED_FULL)
			urb->interval /= 8;
	}

	if (HCC_CFC(xhci->hcc_params) && !list_empty(&ep_ring->td_list)) {
		if ((le32_to_cpu(ep_ctx->ep_info) & EP_STATE_MASK) ==
				EP_STATE_RUNNING) {
			urb->start_frame = xep->next_frame_id;
			goto skip_start_over;
		}
	}

	start_frame = readl(&xhci->run_regs->microframe_index);
	start_frame &= 0x3fff;
	 
	ist = HCS_IST(xhci->hcs_params2) & 0x7;
	if (HCS_IST(xhci->hcs_params2) & (1 << 3))
		ist <<= 3;
	start_frame += ist + XHCI_CFC_DELAY;
	start_frame = roundup(start_frame, 8);

	if (urb->dev->speed == USB_SPEED_LOW ||
			urb->dev->speed == USB_SPEED_FULL) {
		start_frame = roundup(start_frame, urb->interval << 3);
		urb->start_frame = start_frame >> 3;
	} else {
		start_frame = roundup(start_frame, urb->interval);
		urb->start_frame = start_frame;
	}

skip_start_over:
	ep_ring->num_trbs_free_temp = ep_ring->num_trbs_free;

	return xhci_queue_isoc_tx(xhci, mem_flags, urb, slot_id, ep_index);
}

static int queue_command(struct xhci_hcd *xhci, struct xhci_command *cmd,
			 u32 field1, u32 field2,
			 u32 field3, u32 field4, bool command_must_succeed)
{
	int reserved_trbs = xhci->cmd_ring_reserved_trbs;
	int ret;

	if ((xhci->xhc_state & XHCI_STATE_DYING) ||
		(xhci->xhc_state & XHCI_STATE_HALTED)) {
		xhci_dbg(xhci, "xHCI dying or halted, can't queue_command\n");
		return -ESHUTDOWN;
	}

	if (!command_must_succeed)
		reserved_trbs++;

	ret = prepare_ring(xhci, xhci->cmd_ring, EP_STATE_RUNNING,
			reserved_trbs, GFP_ATOMIC);
	if (ret < 0) {
		xhci_err(xhci, "ERR: No room for command on command ring\n");
		if (command_must_succeed)
			xhci_err(xhci, "ERR: Reserved TRB counting for "
					"unfailable commands failed.\n");
		return ret;
	}

	cmd->command_trb = xhci->cmd_ring->enqueue;
	list_add_tail(&cmd->cmd_list, &xhci->cmd_list);

	if (xhci->cmd_list.next == &cmd->cmd_list &&
	    !delayed_work_pending(&xhci->cmd_timer)) {
		xhci->current_cmd = cmd;
		xhci_mod_cmd_timer(xhci, XHCI_CMD_DEFAULT_TIMEOUT);
	}

	queue_trb(xhci, xhci->cmd_ring, false, field1, field2, field3,
			field4 | xhci->cmd_ring->cycle_state);
	return 0;
}

int xhci_queue_slot_control(struct xhci_hcd *xhci, struct xhci_command *cmd,
		u32 trb_type, u32 slot_id)
{
	return queue_command(xhci, cmd, 0, 0, 0,
			TRB_TYPE(trb_type) | SLOT_ID_FOR_TRB(slot_id), false);
}

int xhci_queue_address_device(struct xhci_hcd *xhci, struct xhci_command *cmd,
		dma_addr_t in_ctx_ptr, u32 slot_id, enum xhci_setup_dev setup)
{
	return queue_command(xhci, cmd, lower_32_bits(in_ctx_ptr),
			upper_32_bits(in_ctx_ptr), 0,
			TRB_TYPE(TRB_ADDR_DEV) | SLOT_ID_FOR_TRB(slot_id)
			| (setup == SETUP_CONTEXT_ONLY ? TRB_BSR : 0), false);
}

int xhci_queue_vendor_command(struct xhci_hcd *xhci, struct xhci_command *cmd,
		u32 field1, u32 field2, u32 field3, u32 field4)
{
	return queue_command(xhci, cmd, field1, field2, field3, field4, false);
}

int xhci_queue_reset_device(struct xhci_hcd *xhci, struct xhci_command *cmd,
		u32 slot_id)
{
	return queue_command(xhci, cmd, 0, 0, 0,
			TRB_TYPE(TRB_RESET_DEV) | SLOT_ID_FOR_TRB(slot_id),
			false);
}

int xhci_queue_configure_endpoint(struct xhci_hcd *xhci,
		struct xhci_command *cmd, dma_addr_t in_ctx_ptr,
		u32 slot_id, bool command_must_succeed)
{
	return queue_command(xhci, cmd, lower_32_bits(in_ctx_ptr),
			upper_32_bits(in_ctx_ptr), 0,
			TRB_TYPE(TRB_CONFIG_EP) | SLOT_ID_FOR_TRB(slot_id),
			command_must_succeed);
}

int xhci_queue_evaluate_context(struct xhci_hcd *xhci, struct xhci_command *cmd,
		dma_addr_t in_ctx_ptr, u32 slot_id, bool command_must_succeed)
{
	return queue_command(xhci, cmd, lower_32_bits(in_ctx_ptr),
			upper_32_bits(in_ctx_ptr), 0,
			TRB_TYPE(TRB_EVAL_CONTEXT) | SLOT_ID_FOR_TRB(slot_id),
			command_must_succeed);
}

int xhci_queue_stop_endpoint(struct xhci_hcd *xhci, struct xhci_command *cmd,
			     int slot_id, unsigned int ep_index, int suspend)
{
	u32 trb_slot_id = SLOT_ID_FOR_TRB(slot_id);
	u32 trb_ep_index = EP_ID_FOR_TRB(ep_index);
	u32 type = TRB_TYPE(TRB_STOP_RING);
	u32 trb_suspend = SUSPEND_PORT_FOR_TRB(suspend);

	return queue_command(xhci, cmd, 0, 0, 0,
			trb_slot_id | trb_ep_index | type | trb_suspend, false);
}

void xhci_queue_new_dequeue_state(struct xhci_hcd *xhci,
		unsigned int slot_id, unsigned int ep_index,
		unsigned int stream_id,
		struct xhci_dequeue_state *deq_state)
{
	dma_addr_t addr;
	u32 trb_slot_id = SLOT_ID_FOR_TRB(slot_id);
	u32 trb_ep_index = EP_ID_FOR_TRB(ep_index);
	u32 trb_stream_id = STREAM_ID_FOR_TRB(stream_id);
	u32 trb_sct = 0;
	u32 type = TRB_TYPE(TRB_SET_DEQ);
	struct xhci_virt_ep *ep;
	struct xhci_command *cmd;
	int ret;

	xhci_dbg_trace(xhci, trace_xhci_dbg_cancel_urb,
		"Set TR Deq Ptr cmd, new deq seg = %p (0x%llx dma), new deq ptr = %p (0x%llx dma), new cycle = %u",
		deq_state->new_deq_seg,
		(unsigned long long)deq_state->new_deq_seg->dma,
		deq_state->new_deq_ptr,
		(unsigned long long)xhci_trb_virt_to_dma(
			deq_state->new_deq_seg, deq_state->new_deq_ptr),
		deq_state->new_cycle_state);

	addr = xhci_trb_virt_to_dma(deq_state->new_deq_seg,
				    deq_state->new_deq_ptr);
	if (addr == 0) {
		xhci_warn(xhci, "WARN Cannot submit Set TR Deq Ptr\n");
		xhci_warn(xhci, "WARN deq seg = %p, deq pt = %p\n",
			  deq_state->new_deq_seg, deq_state->new_deq_ptr);
		return;
	}
	ep = &xhci->devs[slot_id]->eps[ep_index];
	if ((ep->ep_state & SET_DEQ_PENDING)) {
		xhci_warn(xhci, "WARN Cannot submit Set TR Deq Ptr\n");
		xhci_warn(xhci, "A Set TR Deq Ptr command is pending.\n");
		return;
	}

	cmd = xhci_alloc_command(xhci, false, false, GFP_ATOMIC);
	if (!cmd) {
		xhci_warn(xhci, "WARN Cannot submit Set TR Deq Ptr: ENOMEM\n");
		return;
	}

	ep->queued_deq_seg = deq_state->new_deq_seg;
	ep->queued_deq_ptr = deq_state->new_deq_ptr;
	if (stream_id)
		trb_sct = SCT_FOR_TRB(SCT_PRI_TR);
	ret = queue_command(xhci, cmd,
		lower_32_bits(addr) | trb_sct | deq_state->new_cycle_state,
		upper_32_bits(addr), trb_stream_id,
		trb_slot_id | trb_ep_index | type, false);
	if (ret < 0) {
		xhci_free_command(xhci, cmd);
		return;
	}

	ep->ep_state |= SET_DEQ_PENDING;
}

int xhci_queue_reset_ep(struct xhci_hcd *xhci, struct xhci_command *cmd,
			int slot_id, unsigned int ep_index)
{
	u32 trb_slot_id = SLOT_ID_FOR_TRB(slot_id);
	u32 trb_ep_index = EP_ID_FOR_TRB(ep_index);
	u32 type = TRB_TYPE(TRB_RESET_EP);

	return queue_command(xhci, cmd, 0, 0, 0,
			trb_slot_id | trb_ep_index | type, false);
}

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/client/sharedport"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
)

// queryReadyAfterBlowfish sends the parent master a DC_QUERY_READY, which has a
// payload and a reply, over the inherited family session after first making
// BLOWFISH the master's preferred method for that session. A C++ daemon keys
// the session once per method; resuming it while naming BLOWFISH (as a UDP
// command does, since UDP forces BLOWFISH) makes BLOWFISH the preferred method
// (DaemonCommandProtocol::ReadCommand). The cedar client then has to name AES
// for the master to read its payload. It returns "ok" or what failed.
func queryReadyAfterBlowfish(ctx context.Context, parentAddr string) string {
	sid := security.GetFamilySessionID()
	if sid == "" {
		return "no_family_session"
	}
	spc := sharedport.NewSharedPortClient("childalive-helper")

	// Resume naming BLOWFISH, then hang up: the master records the preference
	// before it reads the payload.
	s, err := spc.ConnectToHTCondorAddress(ctx, parentAddr, 5*time.Second)
	if err != nil {
		return fmt.Sprintf("connect_error:%v", err)
	}
	resumeAd := classad.New()
	_ = resumeAd.Set("Command", commands.DC_QUERY_READY)
	_ = resumeAd.Set("UseSession", "YES")
	_ = resumeAd.Set("Sid", sid)
	_ = resumeAd.Set("ResumeResponse", true)
	_ = resumeAd.Set("RemoteVersion", security.DefaultRemoteVersion)
	_ = resumeAd.Set("CryptoMethods", "BLOWFISH")
	msg := message.NewMessageForStream(s)
	if err := msg.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
		return fmt.Sprintf("blowfish_resume_error:%v", err)
	}
	if err := msg.PutClassAd(ctx, resumeAd); err != nil {
		return fmt.Sprintf("blowfish_resume_error:%v", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Sprintf("blowfish_resume_error:%v", err)
	}
	resp, err := message.NewMessageFromStream(s).GetClassAd(ctx)
	_ = s.Close()
	if err != nil {
		return fmt.Sprintf("blowfish_resume_response_error:%v", err)
	}
	if rc, _ := resp.EvaluateAttrString("ReturnCode"); rc != "AUTHORIZED" {
		return fmt.Sprintf("blowfish_resume_refused:%s", rc)
	}

	// Now the real command, resuming the same session through cedar.
	s, err = spc.ConnectToHTCondorAddress(ctx, parentAddr, 5*time.Second)
	if err != nil {
		return fmt.Sprintf("connect_error:%v", err)
	}
	defer func() { _ = s.Close() }()
	neg, err := security.NewAuthenticator(&security.SecurityConfig{
		Authentication: security.SecurityNever,
		Command:        commands.DC_QUERY_READY,
		SessionID:      sid,
	}, s).ClientHandshake(ctx)
	if err != nil {
		return fmt.Sprintf("handshake_error:%v", err)
	}
	if !neg.SessionResumed {
		return "handshake_not_resumed"
	}
	query := classad.New()
	_ = query.Set("WaitTimeout", 0)
	out := message.NewMessageForStream(s)
	if err := out.PutClassAd(ctx, query); err != nil {
		return fmt.Sprintf("query_error:%v", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Sprintf("query_error:%v", err)
	}
	if _, err := message.NewMessageFromStream(s).GetClassAd(ctx); err != nil {
		return fmt.Sprintf("reply_error:%v", err)
	}
	return "ok"
}

package cache

// ServiceDomains maps service_pk keys to their associated domains.
// When a service is blocked for a profile, all listed domains are added to CustomBlocked.
var ServiceDomains = map[string][]string{
	// Social Media
	"facebook":    {"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "m.facebook.com"},
	"youtube":     {"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "yt3.ggpht.com"},
	"instagram":   {"instagram.com", "cdninstagram.com"},
	"tiktok":      {"tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly", "byteoversea.com"},
	"snapchat":    {"snapchat.com", "snap.com", "snapimg.com"},
	"wechat":      {"wechat.com", "weixin.qq.com", "wx.qq.com"},
	"twitter":     {"twitter.com", "x.com", "t.co", "twimg.com"},
	"linkedin":    {"linkedin.com", "lnkd.in", "licdn.com"},
	"pinterest":   {"pinterest.com", "pinimg.com"},
	"reddit":      {"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"},

	// Messaging
	"whatsapp":    {"whatsapp.com", "whatsapp.net"},
	"telegram":    {"telegram.org", "t.me", "telegram.me", "telesco.pe"},
	"discord":     {"discord.com", "discordapp.com", "discord.gg", "discordcdn.com"},
	"messenger":   {"messenger.com"},

	// Gaming
	"steam":       {"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcdn-a.akamaihd.net"},
	"twitch":      {"twitch.tv", "twitchapps.com", "jtvnw.net", "twitchsvc.net"},
	"roblox":      {"roblox.com", "rbxcdn.com", "robloxlabs.com"},
	"epicgames":   {"epicgames.com", "unrealengine.com", "fortnite.com"},
	"xbox":        {"xbox.com", "xboxlive.com", "xsts.auth.xboxlive.com"},
	"playstation": {"playstation.com", "playstation.net", "psnstores.com"},
	"nintendo":    {"nintendo.com", "nintendo.net"},

	// Streaming
	"netflix":     {"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"},
	"spotify":     {"spotify.com", "spotifycdn.com", "scdn.co"},
	"hulu":        {"hulu.com", "hulustream.com"},
	"disneyplus":  {"disneyplus.com", "disney-plus.net", "bamgrid.com"},
	"amazonprime": {"primevideo.com", "amazon.com"},
	"appletv":     {"tv.apple.com", "itunes.apple.com"},

	// Other
	"tumblr":      {"tumblr.com"},
	"vimeo":       {"vimeo.com", "vimeocdn.com"},
	"onlyfans":    {"onlyfans.com"},
}

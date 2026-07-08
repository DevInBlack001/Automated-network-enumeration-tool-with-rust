-- Custom native Lua script plugin for netenum
-- Grabs TCP connection banners

-- Define which ports this script runs on
function applies_to(port)
    return port == 21 or port == 22 or port == 25 or port == 110 or port == 143 or port == 111
end

-- Execute banner grab
function run(host, port)
    netenum.log("Grabbing banner on " .. host .. ":" .. port)
    
    local banner = netenum.tcp_connect(host, port, nil, 1500)
    if not banner or banner == "" then
        return nil, "no banner received"
    end
    
    -- Clean up trailing newlines / whitespaces
    banner = banner:gsub("^%s*(.-)%s*$", "%1")
    -- Limit length to 100 characters for clean printing
    if #banner > 100 then
        banner = banner:sub(1, 97) .. "..."
    end
    
    return "Grabbed Banner: " .. banner
end

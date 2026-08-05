-- Custom native Lua script plugin for netenum
-- Grabs the HTTP HTML page title

-- Define which ports this script runs on
function applies_to(port)
    return port == 80 or port == 8080 or port == 8880 or port == 2379 or port == 8081 or port == 3000
end

-- Execute banner/information extraction
function run(host, port)
    netenum.log("Querying http://" .. host .. ":" .. port .. "/")
    
    local res = netenum.http_get(host, port, "/", 1500)
    if not res then
        return nil, "connection failed"
    end
    
    if res.body then
        -- Find HTML title tag (case-insensitive-like matching)
        local title = res.body:match("<[tT][iI][tT][lL][eE]>(.-)</[tT][iI][tT][lL][eE]>")
        if title then
            -- Clean up whitespace
            title = title:gsub("^%s*(.-)%s*$", "%1")
            return "HTTP Title: '" .. title .. "'"
        end
    end

    -- No title found; the HTTP status line is already captured by netenum's
    -- native banner grab, so don't restate it here.
    return nil, "no title found"
end

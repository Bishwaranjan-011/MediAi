using Microsoft.EntityFrameworkCore;
using MediTrack.Api.Data;
using MediTrack.Api.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Database Connection
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 2. CORS - Allows React (Port 5174) to talk to .NET
builder.Services.AddCors(options => {
    options.AddPolicy("AllowReact", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Middleware
app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("AllowReact");

// --- AUTHENTICATION ROUTES ---

app.MapPost("/api/login", async (AppDbContext db, LoginRequest login) => {
    // 1. Find the user by username first
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == login.Username);

    // 2. If user exists, verify the password hash
    if (user == null || !BCrypt.Net.BCrypt.Verify(login.Password, user.Password))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        Username = user.Username,
        Role = user.Role,
        Token = "secure-session-2026"
    });
});

app.MapPost("/api/register", async (AppDbContext db, User newUser) => {
    if (await db.Users.AnyAsync(u => u.Username == newUser.Username))
        return Results.BadRequest("Username already taken.");

    // HASH THE PASSWORD before saving
    newUser.Password = BCrypt.Net.BCrypt.HashPassword(newUser.Password);

    db.Users.Add(newUser);
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "User created successfully!" });
});

app.MapGet("/api/users", async (AppDbContext db) =>
    await db.Users.ToListAsync());

app.MapDelete("/api/users/{id:int}", async (int id, AppDbContext db) => {
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    // Prevent deleting the last remaining admin if you want to be safe
    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

// --- INVENTORY ROUTES ---

app.MapGet("/api/inventory", async (AppDbContext db) =>
    await db.InventoryItems.ToListAsync());

app.MapPost("/api/inventory", async (AppDbContext db, InventoryItem item) => {
    item.LastUpdated = DateTime.Now;
    db.InventoryItems.Add(item);
    await db.SaveChangesAsync();
    return Results.Created($"/api/inventory/{item.Id}", item);
});

app.MapPut("/api/inventory/{id:int}", async (int id, InventoryItem input, AppDbContext db) => {
    var item = await db.InventoryItems.FindAsync(id);
    if (item is null) return Results.NotFound();

    item.Name = input.Name;
    item.Quantity = input.Quantity;
    item.Category = input.Category;
    item.LastUpdated = DateTime.Now;

    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapDelete("/api/inventory/{id:int}", async (int id, AppDbContext db) => {
    var item = await db.InventoryItems.FindAsync(id);
    if (item is null) return Results.NotFound();
    db.InventoryItems.Remove(item);
    await db.SaveChangesAsync();
    return Results.NoContent();
});


// --- AUTOMATIC ADMIN SEEDER ---
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    context.Database.EnsureCreated();

    // Look for the 'admin' user
    var adminUser = await context.Users.FirstOrDefaultAsync(u => u.Username == "admin");

    if (adminUser == null)
    {
        // Create it if it doesn't exist
        context.Users.Add(new User
        {
            Username = "admin",
            Password = BCrypt.Net.BCrypt.HashPassword("password123"),
            Role = "Admin"
        });
        context.SaveChanges();
    }
    else
    {
        // Optional: Update the existing admin password to be hashed if it isn't already
        adminUser.Password = BCrypt.Net.BCrypt.HashPassword("password123");
        context.SaveChanges();
    }
}

app.Run();

public record LoginRequest(string Username, string Password);
package backdoordetected.detection;

import java.util.Map;
import java.util.Set;

public class BukkitAPIKnowledge {
  private static final Map<String, Set<String>> SAFE_METHODS =
      Map.ofEntries(
          Map.entry(
              "org.bukkit.entity.Player",
              Set.of(
                  "getName",
                  "getUniqueId",
                  "getWorld",
                  "getGameMode",
                  "getHealth",
                  "getMaxHealth",
                  "getLevel",
                  "getExp",
                  "getFoodLevel",
                  "getAddress",
                  "isOp",
                  "hasPermission",
                  "getLocale")),
          Map.entry(
              "org.bukkit.World",
              Set.of(
                  "getName",
                  "getEnvironment",
                  "getDifficulty",
                  "getWorldType",
                  "getSeed",
                  "getSpawnLocation")),
          Map.entry(
              "org.bukkit.Server",
              Set.of(
                  "getName",
                  "getVersion",
                  "getBukkitVersion",
                  "getMotd",
                  "getPort",
                  "getMaxPlayers")),
          Map.entry(
              "org.bukkit.Location",
              Set.of("getWorld", "getX", "getY", "getZ", "getYaw", "getPitch")));

  private static final Map<String, Set<String>> TAINTED_METHODS =
      Map.ofEntries(
          Map.entry(
              "org.bukkit.entity.Player",
              Set.of("getCustomName", "getDisplayName", "getPlayerListName")),
          Map.entry("org.bukkit.event.player.AsyncPlayerChatEvent", Set.of("getMessage")),
          Map.entry("org.bukkit.event.player.PlayerChatEvent", Set.of("getMessage")),
          Map.entry("org.bukkit.event.player.PlayerCommandPreprocessEvent", Set.of("getMessage")),
          Map.entry("org.bukkit.inventory.ItemStack", Set.of("getItemMeta")),
          Map.entry(
              "org.bukkit.inventory.meta.ItemMeta",
              Set.of("getDisplayName", "getLore", "getLocalizedName")),
          Map.entry(
              "org.bukkit.inventory.meta.BookMeta",
              Set.of("getTitle", "getAuthor", "getPages", "getPage")),
          Map.entry("org.bukkit.block.Sign", Set.of("getLine", "getLines")),
          Map.entry("org.bukkit.event.inventory.PrepareAnvilEvent", Set.of("getInventory")));

  public static boolean isSafeMethod(String className, String methodName) {
    if (className == null || methodName == null) {
      return false;
    }
    Set<String> safeMethods = SAFE_METHODS.get(className);
    return safeMethods != null && safeMethods.contains(methodName);
  }

  public static boolean isTaintedMethod(String className, String methodName) {
    if (className == null || methodName == null) {
      return false;
    }

    Set<String> taintedMethods = TAINTED_METHODS.get(className);
    return taintedMethods != null && taintedMethods.contains(methodName);
  }

  public static boolean isBukkitClass(String className) {
    if (className == null) {
      return false;
    }

    return className.startsWith("org.bukkit.")
        || className.startsWith("org.spigotmc.")
        || className.startsWith("net.md_5.bungee.");
  }
}

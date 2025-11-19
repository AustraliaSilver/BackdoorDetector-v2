package backdoordetected;

import org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;

import java.io.File;
import java.util.Map;

public class VineflowerWrapper extends ConsoleDecompiler {
    public VineflowerWrapper(File destination, Map<String, Object> options, IFernflowerLogger logger) {
        super(destination, options, logger);
    }
}
